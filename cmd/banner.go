package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/term"
)

func init() {
	// fatih/color auto-detects TTY, but on some Windows consoles
	// (legacy cmd.exe without ENABLE_VIRTUAL_TERMINAL_PROCESSING,
	// older PowerShell hosts) the auto-detect misses. Forcing colour
	// on is safe because:
	//   - modern Windows 10+ consoles (PowerShell 5.1+, Windows
	//     Terminal, PowerShell 7) all support ANSI natively
	//   - we still skip entirely when stdout isn't a TTY (piped,
	//     redirected)
	//   - NO_COLOR=1 overrides via our explicit check in PrintBanner
	//
	// The tradeoff: if a user on legacy cmd.exe without VT enabled
	// runs argus, they'll see raw escape codes. That audience is
	// tiny and shrinking; bad formatting there is better than
	// nothing for the 99% of users on modern terminals.
	if term.IsTerminal(int(os.Stdout.Fd())) {
		color.NoColor = false
	}
}

// argusBanner is the ASCII-art wordmark shown at the top of every
// interactive command. The "ANSI Shadow" FIGlet font renders well in
// both dark and light terminals and uses only BMP Unicode block-
// drawing characters that work in every modern shell (PowerShell 5.1+,
// Windows Terminal, iTerm2, GNOME Terminal, etc.).
const argusBanner = `
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
`

// argusTagline is the one-line subtitle that renders under the
// wordmark. Short enough to fit on an 80-column terminal with the
// banner itself.
const argusTagline = "Attack chain analysis for Microsoft Azure"

// PrintBanner writes the ARGUS wordmark + tagline to the given
// writer. If the writer isn't a TTY, the banner is skipped entirely
// — piped output (CI, JSON processing pipelines, log aggregators)
// shouldn't get decorative text.
//
// Colours apply a cyan → magenta vertical gradient across the six
// banner rows. The gradient gives the banner real visual pop
// (matches the aesthetic of tools like neofetch / starship without
// being overwhelming). Tagline is bright white with a magenta
// accent "·" separator. Version renders dim so it doesn't compete
// with the wordmark.
//
// NO_COLOR (https://no-color.org) and non-TTY output both bypass
// the gradient — the banner is printed as plain text or skipped
// entirely.
func PrintBanner(w io.Writer) {
	if !isTTY(w) {
		return
	}
	if os.Getenv("NO_COLOR") != "" {
		fmt.Fprint(w, argusBanner)
		fmt.Fprintf(w, "  %s   v%s\n\n", argusTagline, version)
		return
	}

	// Per-row gradient colours. Six banner rows + a blank top and
	// blank bottom. The gradient runs bright cyan at the top through
	// to magenta at the bottom — reads as "cyber security / modern
	// CLI" without being garish.
	gradient := []*color.Color{
		color.New(color.FgHiCyan, color.Bold),
		color.New(color.FgCyan, color.Bold),
		color.New(color.FgHiBlue, color.Bold),
		color.New(color.FgBlue, color.Bold),
		color.New(color.FgHiMagenta, color.Bold),
		color.New(color.FgMagenta, color.Bold),
	}

	lines := strings.Split(strings.Trim(argusBanner, "\n"), "\n")
	fmt.Fprintln(w) // top breathing room
	for i, line := range lines {
		c := gradient[i%len(gradient)]
		_, _ = c.Fprintln(w, line)
	}

	// Tagline: bright white with a magenta separator dot and dim
	// version. The mix of bold-white and dim grey gives the subtitle
	// visual contrast without pulling focus from the wordmark.
	white := color.New(color.FgHiWhite, color.Bold)
	magenta := color.New(color.FgHiMagenta, color.Bold)
	dim := color.New(color.Faint)

	fmt.Fprint(w, "  ")
	_, _ = white.Fprint(w, argusTagline)
	_, _ = magenta.Fprint(w, "  ·  ")
	_, _ = dim.Fprintf(w, "v%s\n", version)
	fmt.Fprintln(w)
}

// PrintCompactBanner writes a one-liner "▶ ARGUS v1.X.Y · tagline"
// for commands where the full banner would be too much vertical
// space (IaC scans, quick status commands). Uses the same cyan →
// magenta accent pair as the full banner for brand consistency.
func PrintCompactBanner(w io.Writer) {
	if !isTTY(w) {
		return
	}
	cyan := color.New(color.FgHiCyan, color.Bold)
	magenta := color.New(color.FgHiMagenta, color.Bold)
	white := color.New(color.FgHiWhite, color.Bold)
	dim := color.New(color.Faint)

	_, _ = cyan.Fprint(w, "▶ ")
	_, _ = white.Fprint(w, "ARGUS")
	_, _ = dim.Fprintf(w, " v%s", version)
	_, _ = magenta.Fprint(w, "  ·  ")
	_, _ = white.Fprintln(w, argusTagline)
}

// isTTY reports whether the writer is an interactive terminal. Used
// to suppress decorative output when stdout is piped to a file, CI
// runner, or other process that shouldn't receive ANSI escapes.
func isTTY(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}
