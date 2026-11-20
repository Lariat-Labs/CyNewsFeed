package feeds

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// SSRF protection: feed URLs and article links are attacker-influenced, so the
// fetch client refuses to connect to internal addresses. The check runs on the
// resolved IP at connect time (net.Dialer.Control), which also covers HTTP
// redirects and DNS rebinding.

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),    // carrier-grade NAT
	netip.MustParsePrefix("168.63.129.16/32"), // Azure platform (WireServer)
	netip.MustParsePrefix("192.0.0.0/24"),     // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),    // benchmarking
	netip.MustParsePrefix("64:ff9b::/96"),     // NAT64 (can map to internal IPv4)
	netip.MustParsePrefix("fc00::/7"),         // unique local
}

// blockedAddr reports whether connecting to ip must be refused.
func blockedAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true // includes 169.254.169.254 (cloud metadata) via link-local
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func safeTransport(allowPrivate bool) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !allowPrivate {
		d.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("refusing to connect to %q", host)
			}
			if blockedAddr(ip) {
				return fmt.Errorf("refusing to connect to internal address %s", ip)
			}
			return nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// No proxy: a proxy would perform the connection and bypass the IP check.
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	return tr
}
