package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	ErrBlockedIP      = errors.New("destination IP is blocked by SSRF policy")
	ErrBlockedHost    = errors.New("destination hostname is blocked by SSRF policy")
	ErrInvalidScheme  = errors.New("only http and https schemes are permitted")
	ErrTooManyRedirects = errors.New("too many redirects")
)

// Blocked CIDR ranges for SSRF mitigation
var blockedCIDRs = []string{
	// IPv4 Loopback
	"127.0.0.0/8",
	// IPv4 Private (RFC 1918)
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// IPv4 Carrier Grade NAT (RFC 6598)
	"100.64.0.0/10",
	// IPv4 Link-Local / Cloud Metadata (RFC 3927)
	"169.254.0.0/16",
	// IPv4 IETF Protocol Assignments
	"192.0.0.0/24",
	// IPv4 Documentation & Benchmarking
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	// IPv4 Multicast & Reserved
	"224.0.0.0/4",
	"240.0.0.0/4",
	"0.0.0.0/8",
	"255.255.255.255/32",
	// Alibaba Cloud Metadata
	"100.100.100.200/32",

	// IPv6 Loopback
	"::1/128",
	// IPv6 Unspecified
	"::/128",
	// IPv6 Link-Local
	"fe80::/10",
	// IPv6 Unique Local Address (ULA)
	"fc00::/7",
	// IPv6 Multicast
	"ff00::/8",
	// IPv6 Documentation
	"2001:db8::/32",
	// IPv6 Discard prefix
	"100::/64",
}

var blockedNets []*net.IPNet

func init() {
	for _, cidr := range blockedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedNets = append(blockedNets, ipNet)
		}
	}
}

// Blocked Hostnames (metadata, local, internal)
var blockedHostnames = map[string]struct{}{
	"localhost":                {},
	"metadata.google.internal": {},
	"metadata.internal":        {},
	"instance-data":            {},
}

// IsBlockedHost checks if a hostname or domain should be blocked.
func IsBlockedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if _, ok := blockedHostnames[host]; ok {
		return true
	}

	if strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".corp") ||
		strings.HasSuffix(host, ".lan") {
		return true
	}

	// Check if the host is directly an IP
	if ip := net.ParseIP(host); ip != nil {
		return IsBlockedIP(ip)
	}

	return false
}

// IsBlockedIP checks if an IP address falls into private, loopback, link-local, or cloud metadata ranges.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Canonicalize IPv4-mapped IPv6
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	for _, ipNet := range blockedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// ValidateTargetURL parses and validates that a target URL is safe to fetch.
func ValidateTargetURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, ErrInvalidScheme
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, errors.New("missing hostname in URL")
	}

	if IsBlockedHost(hostname) {
		return nil, fmt.Errorf("%w: %s", ErrBlockedHost, hostname)
	}

	return parsed, nil
}

// SafeDialer creates a net.Dialer that prevents DNS Rebinding and SSRF attacks.
func SafeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return nil
		},
	}
}

// SafeHTTPClient returns an http.Client configured to prevent SSRF, enforce timeouts, and limit redirects.
func SafeHTTPClient(timeout time.Duration, maxRedirects int) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if maxRedirects <= 0 {
		maxRedirects = 5
	}

	dialer := SafeDialer(timeout)

	transport := &http.Transport{
		Proxy:                 nil, // Do not inherit environmental HTTP_PROXY blindly
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			if IsBlockedHost(host) {
				return nil, fmt.Errorf("%w: %s", ErrBlockedHost, host)
			}

			// Resolve IPs and check all candidates
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for %s", host)
			}

			var safeIP net.IP
			for _, ip := range ips {
				if !IsBlockedIP(ip) {
					safeIP = ip
					break
				}
			}

			if safeIP == nil {
				return nil, fmt.Errorf("%w: all resolved IPs for %s are forbidden", ErrBlockedIP, host)
			}

			// Dial specifically the verified safe IP to defeat DNS Rebinding
			targetAddr := net.JoinHostPort(safeIP.String(), port)
			return dialer.DialContext(ctx, network, targetAddr)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyRedirects
			}
			if _, err := ValidateTargetURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
}
