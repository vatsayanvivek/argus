package azure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// PreflightResult describes the outcome of a connectivity probe run
// before the heavy scan begins. It deliberately separates "can we
// reach the endpoint at all" from "do we have credentials" so the
// CLI can render an actionable message instead of a cryptic SDK
// error after a 60-second hang.
type PreflightResult struct {
	OK               bool
	Endpoints        []EndpointStatus
	DiagnosticHint   string // user-facing explanation when !OK
	ProxyDetected    string // value of HTTPS_PROXY if set
	TotalElapsed     time.Duration
}

// EndpointStatus records one endpoint's probe outcome.
type EndpointStatus struct {
	Name       string
	URL        string
	OK         bool
	StatusCode int
	Error      string
	Elapsed    time.Duration
}

// Preflight runs a short connectivity + auth probe against the Azure
// endpoints ARGUS actually uses. The probe has a short timeout (5s
// per endpoint, 20s total) so users see a clear failure fast, not a
// silent 60+-second hang ending in "context deadline exceeded".
//
// The probe is deliberately cheap: TCP reachability + an unauthenticated
// GET against well-known public endpoints. We don't evaluate RBAC
// here — that's the scan's job — we just answer "is the network path
// to Azure actually open from this machine".
//
// Common causes of preflight failure in enterprise environments:
//   - Corporate HTTPS proxy requiring explicit HTTPS_PROXY
//   - Windows Defender Network Protection inspecting + blocking
//   - Zscaler / Netskope / other CASB in-path
//   - Corporate firewall blocking management.azure.com or graph.microsoft.com
//   - DNS resolver that doesn't resolve Azure public endpoints
//
// When any of these are detected Preflight returns !OK with a
// DiagnosticHint that names the likely culprit.
func Preflight(ctx context.Context) PreflightResult {
	start := time.Now()
	result := PreflightResult{
		ProxyDetected: detectProxy(),
	}
	// Bound the whole preflight to 20s so it can't itself hang.
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	probes := []struct {
		name, url string
	}{
		{"Azure ARM (management.azure.com)", "https://management.azure.com/metadata/endpoints?api-version=2022-01-01"},
		{"Microsoft Graph (graph.microsoft.com)", "https://graph.microsoft.com/v1.0/$metadata"},
		{"Azure AD login (login.microsoftonline.com)", "https://login.microsoftonline.com/organizations/.well-known/openid-configuration"},
	}

	client := &http.Client{Timeout: 5 * time.Second}
	anyOK := false
	for _, p := range probes {
		status := probeEndpoint(probeCtx, client, p.name, p.url)
		result.Endpoints = append(result.Endpoints, status)
		if status.OK {
			anyOK = true
		}
	}
	result.OK = anyOK
	result.TotalElapsed = time.Since(start)

	if !result.OK {
		result.DiagnosticHint = diagnoseFailure(result)
	}
	return result
}

// probeEndpoint fires one GET and classifies the outcome. An HTTP
// status in 200-499 means we reached the endpoint (even 401/403/404
// proves connectivity). 5xx or connection-level errors fail the
// probe.
func probeEndpoint(ctx context.Context, client *http.Client, name, u string) EndpointStatus {
	start := time.Now()
	status := EndpointStatus{Name: name, URL: u}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		status.Error = err.Error()
		status.Elapsed = time.Since(start)
		return status
	}
	resp, err := client.Do(req)
	status.Elapsed = time.Since(start)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer resp.Body.Close()
	status.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		status.OK = true
	} else {
		status.Error = fmt.Sprintf("unexpected HTTP %d", resp.StatusCode)
	}
	return status
}

// diagnoseFailure walks the probe errors and picks the most likely
// root cause. The hint is worded to be actionable and agnostic of
// specific vendor products — every enterprise has *some* endpoint
// security / network inspection / proxy / DLP / CASB in the path,
// so we describe the symptom and let the user match to whichever
// product is in their environment.
func diagnoseFailure(r PreflightResult) string {
	requiredDomains := "\nDomains ARGUS needs to reach on TCP 443:\n" +
		"   - management.azure.com\n" +
		"   - graph.microsoft.com\n" +
		"   - login.microsoftonline.com"

	// Look for specific error signatures.
	for _, e := range r.Endpoints {
		if e.Error == "" {
			continue
		}
		low := strings.ToLower(e.Error)

		switch {
		case strings.Contains(low, "no such host"),
			strings.Contains(low, "dns"),
			strings.Contains(low, "resolve"):
			return fmt.Sprintf(
				"DNS resolution failed for %s. The local resolver did not return an answer. "+
					"Common causes: split-horizon DNS that blocks public endpoints, a VPN that rewrites "+
					"resolution, or being offline. Verify with 'nslookup management.azure.com' from "+
					"this machine — if that fails, DNS is the cause.", trimURL(e.URL))

		case strings.Contains(low, "context deadline exceeded"),
			strings.Contains(low, "timeout"),
			strings.Contains(low, "deadline exceeded"):
			if r.ProxyDetected != "" {
				return fmt.Sprintf(
					"Timed out reaching Azure via the configured proxy (%s) after %s. The proxy may "+
						"require authentication credentials (use HTTPS_PROXY=http://user:pass@host:port), "+
						"or it may be inspecting TLS traffic and stalling. Try disabling HTTPS_PROXY for "+
						"a direct-route test if your network allows it.",
					r.ProxyDetected, e.Elapsed.Round(time.Second))
			}
			return fmt.Sprintf(
				"The request hung for %s without response from the Azure endpoint. In enterprise "+
					"environments this pattern is typical when:\n"+
					"  1. Endpoint-security or network-inspection software on this host is intercepting "+
					"the HTTPS traffic and introducing delay (any AV / EDR / DLP / network-protection "+
					"feature can do this)\n"+
					"  2. A corporate proxy or CASB is in the path but not configured — set "+
					"HTTPS_PROXY=http://<proxy-host>:<port> so ARGUS routes through it\n"+
					"  3. A firewall rule is silently dropping outbound traffic on 443 to the Azure "+
					"public endpoints\n"+
					"\n"+
					"Diagnostic suggestions:\n"+
					"  - 'curl -v https://management.azure.com/' from this machine — if that times out "+
					"too, the problem is network-wide, not argus-specific\n"+
					"  - Ask your IT team whether outbound HTTPS to Azure management endpoints is "+
					"restricted or intercepted on this network segment"+
					"%s", e.Elapsed.Round(time.Second), requiredDomains)

		case strings.Contains(low, "tls"),
			strings.Contains(low, "certificate"),
			strings.Contains(low, "x509"),
			strings.Contains(low, "handshake"):
			return "TLS handshake with the upstream endpoint failed. This typically means a " +
				"TLS-inspecting intermediary is in the network path (any corporate gateway that " +
				"decrypts HTTPS traffic for inspection falls into this category) and its root CA " +
				"certificate is not present in the system trust store. If your organisation uses " +
				"TLS inspection, ask IT for the corporate root CA and install it, or request " +
				"that the Azure management domains bypass TLS inspection."

		case strings.Contains(low, "connection refused"),
			strings.Contains(low, "network is unreachable"):
			return "The connection to the Azure endpoint was actively refused. This is almost " +
				"always a firewall rule between this host and the public internet blocking outbound " +
				"traffic on 443. Ask IT to verify that the host's network segment is permitted to " +
				"reach the Azure management and Graph endpoints." + requiredDomains

		case strings.Contains(low, "proxyconnect"):
			return fmt.Sprintf("The configured proxy (%s) rejected the connection. The proxy may "+
				"require authentication, or it may not accept traffic from this source network. "+
				"Verify the HTTPS_PROXY URL + credentials, and ask IT whether this host is "+
				"authorised to use the proxy.", r.ProxyDetected)
		}
	}

	// Generic fallback when we can't fingerprint the error.
	return "The Azure endpoints could not be reached within the preflight window. Verify " +
		"network connectivity, proxy configuration, and that your host is permitted to make " +
		"outbound HTTPS connections to the Azure management and Graph endpoints." + requiredDomains
}

// detectProxy returns the first proxy env var set (HTTPS_PROXY,
// HTTP_PROXY, ALL_PROXY) or empty string if none. The returned
// string is shown to the user so they can see what Go's HTTP stack
// will actually use.
func detectProxy() string {
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
		if s := os.Getenv(v); s != "" {
			// Sanitise: don't display the password portion if present.
			if u, err := url.Parse(s); err == nil && u.User != nil {
				u.User = url.User(u.User.Username())
				return u.String()
			}
			return s
		}
	}
	return ""
}

// trimURL returns the scheme+host portion of a URL for display.
func trimURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	return parsed.Scheme + "://" + parsed.Host
}

// PreflightAuth runs a quick credential check after network
// reachability is confirmed. Fires one token-acquire call against
// the ARM endpoint — tells the user immediately if their credential
// chain is broken, rather than after the 5-collector fan-out
// produces five near-identical error messages.
func PreflightAuth(ctx context.Context) error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("no Azure credential available. Run `az login` or set environment "+
			"variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET) before scanning. "+
			"Full error: %w", err)
	}

	authCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err = cred.GetToken(authCtx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		low := strings.ToLower(err.Error())
		switch {
		case strings.Contains(low, "aadsts700082"), strings.Contains(low, "refresh token has expired"):
			return fmt.Errorf("your cached Azure credentials have expired. Run `az login` again and retry")
		case strings.Contains(low, "aadsts50076"), strings.Contains(low, "mfa"):
			return fmt.Errorf("MFA required for scanning identity. Complete MFA in `az login` " +
				"or configure a Service Principal with AZURE_CLIENT_SECRET")
		case strings.Contains(low, "aadsts50034"), strings.Contains(low, "user account does not exist"):
			return fmt.Errorf("the scanning user doesn't exist in the target tenant. Check --tenant value")
		case strings.Contains(low, "aadsts7000215"), strings.Contains(low, "invalid client secret"):
			return fmt.Errorf("AZURE_CLIENT_SECRET is invalid or expired. Regenerate in the Azure portal")
		case errors.Is(err, context.DeadlineExceeded):
			return fmt.Errorf("timed out acquiring Azure token after 15s. Likely cause: proxy " +
				"or network is intercepting the login.microsoftonline.com traffic")
		}
		return fmt.Errorf("Azure authentication failed: %w", err)
	}
	return nil
}

// netError is a type-assertion helper the diagnose logic could use if
// it wanted to inspect specific net.Error behaviour. Exported purely
// so it's easy to extend the diagnosis later without touching the
// caller-facing surface.
var _ net.Error = (*net.OpError)(nil)
