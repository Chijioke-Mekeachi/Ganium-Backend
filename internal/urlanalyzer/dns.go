package urlanalyzer

import (
	"context"
	"net"
	"strings"
	"time"

	"ganium/internal/security"
	"ganium/pkg/types"
	"golang.org/x/net/idna"
)

// DNSInspector resolves DNS records and checks domain properties.
type DNSInspector struct {
	resolver *net.Resolver
	timeout  time.Duration
}

func NewDNSInspector(timeout time.Duration) *DNSInspector {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &DNSInspector{
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}
}

// InspectDomain performs DNS record queries and domain metadata extraction.
func (d *DNSInspector) InspectDomain(ctx context.Context, hostname string) (types.DomainEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	hostname = strings.ToLower(strings.TrimSpace(hostname))
	// Strip port if present
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}

	evidence := types.DomainEvidence{
		Name: hostname,
	}

	// Check Punycode / IDN
	if strings.HasPrefix(hostname, "xn--") || strings.Contains(hostname, ".xn--") {
		evidence.Punycode = true
		if unicodeHost, err := idna.ToUnicode(hostname); err == nil {
			evidence.Name = unicodeHost + " (" + hostname + ")"
		}
	}

	// Extract TLD and Subdomain
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		evidence.TLD = "." + parts[len(parts)-1]
		if len(parts) > 2 {
			evidence.Subdomain = strings.Join(parts[:len(parts)-2], ".")
		}
	}

	// Detect Homoglyphs (Cyrillic, Greek lookalikes in Latin-looking domains)
	evidence.Homoglyph = DetectHomoglyphs(hostname)

	// Check if blocked host
	if security.IsBlockedHost(hostname) {
		evidence.IPAddresses = []string{"BLOCKED_INTERNAL_OR_LOOPBACK"}
		return evidence, nil
	}

	// Resolve A & AAAA Records
	ips, err := d.resolver.LookupIP(ctx, "ip", hostname)
	if err == nil {
		for _, ip := range ips {
			evidence.IPAddresses = append(evidence.IPAddresses, ip.String())
		}
		if len(evidence.IPAddresses) > 0 {
			evidence.DNSRecords = append(evidence.DNSRecords, types.DNSRecord{
				Type: "A/AAAA",
				Data: evidence.IPAddresses,
			})
		}
	}

	// Resolve NS Records
	nsList, err := d.resolver.LookupNS(ctx, hostname)
	if err == nil && len(nsList) > 0 {
		for _, ns := range nsList {
			evidence.Nameservers = append(evidence.Nameservers, ns.Host)
		}
		evidence.DNSRecords = append(evidence.DNSRecords, types.DNSRecord{
			Type: "NS",
			Data: evidence.Nameservers,
		})
	}

	// Resolve MX Records
	mxList, err := d.resolver.LookupMX(ctx, hostname)
	if err == nil && len(mxList) > 0 {
		var mxData []string
		for _, mx := range mxList {
			mxData = append(mxData, mx.Host)
		}
		evidence.DNSRecords = append(evidence.DNSRecords, types.DNSRecord{
			Type: "MX",
			Data: mxData,
		})
	}

	// Resolve TXT Records
	txtList, err := d.resolver.LookupTXT(ctx, hostname)
	if err == nil && len(txtList) > 0 {
		evidence.DNSRecords = append(evidence.DNSRecords, types.DNSRecord{
			Type: "TXT",
			Data: txtList,
		})
	}

	// Check Dynamic DNS providers
	dynamicDNSHosts := []string{"duckdns.org", "no-ip.com", "ngrok.io", "localtunnel.me", "serveo.net", "pagekite.me"}
	for _, dyn := range dynamicDNSHosts {
		if strings.HasSuffix(hostname, dyn) {
			evidence.IsDynamicDNS = true
			break
		}
	}

	return evidence, nil
}

// DetectHomoglyphs checks for mixed script homoglyph / IDN spoofing.
func DetectHomoglyphs(s string) bool {
	var hasLatin, hasNonLatin bool
	for _, r := range s {
		if r == '.' || r == '-' || (r >= '0' && r <= '9') {
			continue
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLatin = true
		} else if (r >= 0x0400 && r <= 0x04FF) || // Cyrillic
			(r >= 0x0370 && r <= 0x03FF) || // Greek
			(r >= 0x0530 && r <= 0x058F) { // Armenian
			hasNonLatin = true
		}
	}
	return hasLatin && hasNonLatin
}
