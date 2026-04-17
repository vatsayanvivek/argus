package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// updateCmd is `argus update` — a self-updater that swaps the running
// binary for a newer (or older, via --version) release without
// requiring the user to download anything manually or re-run the
// installer. Works on every platform the project ships for.
//
// Flow:
//   1. Query the GitHub releases API for the target release
//   2. Pick the right asset for runtime.GOOS / runtime.GOARCH
//   3. Download the binary + SHA256SUMS to a temp file
//   4. Verify the SHA-256 matches the published checksum
//   5. Atomically replace the running executable (Windows uses the
//      rename-old-out trick because you can't overwrite a running exe)
//
// No admin rights required on any platform — the binary is replaced
// in whatever location it was installed to (typically a user-scope
// directory after `argus install`).
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Upgrade this argus binary to the latest (or a specific) release",
	Long: `Download a newer release from GitHub, verify its SHA-256 hash, and
atomically replace the running executable.

Examples:
  argus update                       # upgrade to the latest release
  argus update --version v1.0.0      # pin to a specific version
  argus update --list                # show available versions
  argus update --check               # report latest without installing

No admin / sudo required. The binary is replaced in the same directory
it currently lives in, so installs to ~/.local/bin/argus or
%LOCALAPPDATA%\Programs\argus\argus.exe both work.`,
	RunE: runUpdate,
}

var (
	updateVersion string
	updateList    bool
	updateCheck   bool
	updateForce   bool
)

const (
	githubOwner = "vatsayanvivek"
	githubRepo  = "argus"
)

func init() {
	updateCmd.Flags().StringVar(&updateVersion, "version", "", "Install a specific release tag (e.g. v1.0.0). Default: latest.")
	updateCmd.Flags().BoolVar(&updateList, "list", false, "List available release versions and exit")
	updateCmd.Flags().BoolVar(&updateCheck, "check", false, "Print the latest version without installing")
	updateCmd.Flags().BoolVar(&updateForce, "force", false, "Reinstall even if the requested version matches the current binary")
	rootCmd.AddCommand(updateCmd)
}

// githubRelease is the narrow view of a release we decode from the
// GitHub API response. We skip fields we don't use (release body,
// author, etc.) so an API schema change is less likely to break us.
type githubRelease struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Draft       bool           `json:"draft"`
	Prerelease  bool           `json:"prerelease"`
	PublishedAt time.Time      `json:"published_at"`
	Assets      []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	if updateList {
		return listReleases(ctx)
	}

	// Resolve the target release. When --version is empty we use the
	// "latest" endpoint; otherwise we fetch the specific tag so we can
	// downgrade if the user asks.
	release, err := resolveRelease(ctx, updateVersion)
	if err != nil {
		return err
	}

	if updateCheck {
		fmt.Printf("Latest release: %s\n", green(release.TagName))
		fmt.Printf("  Current:       %s\n", version)
		fmt.Printf("  Published:     %s\n", dim(release.PublishedAt.Format(time.RFC3339)))
		if release.TagName == "v"+version {
			fmt.Println(green("\nYou're on the latest release."))
		} else {
			fmt.Println(yellow("\nRun `argus update` to upgrade."))
		}
		return nil
	}

	// Skip no-op upgrades unless --force is passed.
	if !updateForce && release.TagName == "v"+version {
		fmt.Printf("Already on %s — nothing to do. Use --force to reinstall.\n", green(release.TagName))
		return nil
	}

	asset, err := pickAsset(release, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}

	fmt.Printf("Upgrading from %s to %s...\n", dim(version), green(release.TagName))
	fmt.Printf("  Asset: %s (%s)\n", asset.Name, humanBytes(asset.Size))

	// Download the asset to a temp file alongside the current binary.
	// Staging in the same directory makes the final rename atomic —
	// os.Rename across filesystems would fail silently on some OSes.
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(selfPath); err == nil {
		selfPath = resolved
	}
	installDir := filepath.Dir(selfPath)
	tmpPath := filepath.Join(installDir, "argus.new.tmp")

	if err := downloadFile(ctx, asset.BrowserDownloadURL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download asset: %w", err)
	}

	// Verify SHA-256 against the release's SHA256SUMS file if present.
	// A missing SHA256SUMS falls through with a warning rather than
	// aborting — some older releases predate it.
	if err := verifyAssetHash(ctx, release, asset.Name, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("verify hash: %w", err)
	}

	// Make sure the temp binary is executable before we swap it in.
	// On Windows, file permissions aren't enforced the same way, but
	// chmod is a no-op there.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmpPath, 0o755)
	}

	// Atomic swap.
	if err := atomicReplace(selfPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("swap binary: %w", err)
	}

	fmt.Println()
	fmt.Printf("%s Upgraded to %s. New binary is at %s\n",
		green("✓"), green(release.TagName), selfPath)
	fmt.Println(dim("Re-run your last command to use the new version."))
	return nil
}

// listReleases prints every published release tag (newest first).
func listReleases(ctx context.Context) error {
	releases, err := fetchReleases(ctx)
	if err != nil {
		return err
	}
	sort.SliceStable(releases, func(i, j int) bool {
		return releases[i].PublishedAt.After(releases[j].PublishedAt)
	})
	green := color.New(color.FgGreen).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()
	fmt.Println("Available releases:")
	for _, r := range releases {
		if r.Draft {
			continue
		}
		marker := "  "
		if r.TagName == "v"+version {
			marker = green(" ▸")
		}
		tag := r.TagName
		if r.Prerelease {
			tag = fmt.Sprintf("%s %s", tag, dim("(pre-release)"))
		}
		fmt.Printf("%s %-20s %s\n", marker, tag, dim(r.PublishedAt.Format("2006-01-02")))
	}
	return nil
}

// resolveRelease returns the GitHub release matching tag, or the
// "latest" release when tag is empty. The tag is normalised to
// "v..." prefix if the user supplied a bare number.
func resolveRelease(ctx context.Context, tag string) (*githubRelease, error) {
	var url string
	if tag == "" {
		url = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", githubOwner, githubRepo)
	} else {
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		url = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", githubOwner, githubRepo, tag)
	}
	release, err := fetchReleaseJSON(ctx, url)
	if err != nil {
		if tag == "" {
			return nil, fmt.Errorf("fetch latest release: %w", err)
		}
		return nil, fmt.Errorf("fetch release %s: %w", tag, err)
	}
	return release, nil
}

func fetchReleaseJSON(ctx context.Context, url string) (*githubRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "argus-self-updater/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("release not found (HTTP 404). Check `argus update --list` for available versions")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var r githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("decode release JSON: %w", err)
	}
	return &r, nil
}

func fetchReleases(ctx context.Context) ([]githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=50", githubOwner, githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "argus-self-updater/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rs []githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return nil, err
	}
	return rs, nil
}

// pickAsset selects the right release asset for the current
// GOOS/GOARCH. Asset naming convention (matches the Makefile /
// release workflow):
//
//	argus-linux-amd64
//	argus-linux-arm64
//	argus-darwin-amd64
//	argus-darwin-arm64
//	argus-windows-amd64.exe
//	argus-windows-arm64.exe
func pickAsset(r *githubRelease, goos, goarch string) (*releaseAsset, error) {
	suffix := ""
	if goos == "windows" {
		suffix = ".exe"
	}
	target := fmt.Sprintf("argus-%s-%s%s", goos, goarch, suffix)

	for i := range r.Assets {
		if r.Assets[i].Name == target {
			return &r.Assets[i], nil
		}
	}
	return nil, fmt.Errorf(
		"release %s doesn't include an asset for %s/%s. Looking for %q in:\n  %s",
		r.TagName, goos, goarch, target, strings.Join(assetNames(r.Assets), "\n  "))
}

func assetNames(as []releaseAsset) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Name
	}
	return out
}

// downloadFile fetches url and writes the body to destPath. Progress
// bytes are not shown — the full download is typically under 30 MB
// and takes a few seconds on any modern connection.
func downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "argus-self-updater/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, url)
	}
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// verifyAssetHash fetches SHA256SUMS from the release, parses it,
// computes the SHA-256 of the local file, and compares. A missing
// SHA256SUMS returns nil (warning printed) so very old releases still
// work, but any mismatch aborts.
func verifyAssetHash(ctx context.Context, release *githubRelease, assetName, localPath string) error {
	var sumsAsset *releaseAsset
	for i := range release.Assets {
		if release.Assets[i].Name == "SHA256SUMS" {
			sumsAsset = &release.Assets[i]
			break
		}
	}
	if sumsAsset == nil {
		fmt.Println("  Warning: release has no SHA256SUMS file; skipping hash verification.")
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsAsset.BrowserDownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "argus-self-updater/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse "hex-hash  filename" lines, find our asset.
	var expected string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == assetName || fields[1] == "*"+assetName {
			expected = strings.ToLower(fields[0])
			break
		}
	}
	if expected == "" {
		fmt.Printf("  Warning: SHA256SUMS has no entry for %s; skipping hash verification.\n", assetName)
		return nil
	}

	// Compute actual hash of downloaded file.
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))

	if actual != expected {
		return fmt.Errorf("hash mismatch for %s\n  expected: %s\n  actual:   %s",
			assetName, expected, actual)
	}
	fmt.Println("  SHA-256 verified.")
	return nil
}

// atomicReplace swaps the running binary with the freshly downloaded
// one. The tricky part is Windows, which doesn't let you overwrite a
// running exe — the workaround is to rename the current exe to a
// sidecar name (which Windows *does* allow), then rename the new exe
// into its place. The renamed-old exe is cleaned up on next
// invocation by installUpdateCleanup.
func atomicReplace(dst, src string) error {
	if runtime.GOOS == "windows" {
		oldPath := dst + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(dst, oldPath); err != nil {
			return fmt.Errorf("rename current exe out of the way: %w", err)
		}
		if err := os.Rename(src, dst); err != nil {
			// Try to restore the original to minimise damage.
			_ = os.Rename(oldPath, dst)
			return fmt.Errorf("move new exe into place: %w", err)
		}
		// .old will be cleaned up on next process start.
		return nil
	}
	// Unix: straight rename works even for a running binary.
	return os.Rename(src, dst)
}

// humanBytes is a tiny formatter so download progress reads nicely.
func humanBytes(n int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/GB)
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.0f KB", float64(n)/KB)
	}
	return fmt.Sprintf("%d B", n)
}
