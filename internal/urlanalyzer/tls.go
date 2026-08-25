package urlanalyzer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"ganium/internal/security"
	"ganium/pkg/types"
)

// TLSInspector connects via TLS to inspect certificates.
type TLSInspector struct {
	timeout time.Duration
}

func NewTLSInspector(timeout time.Duration) *TLSInspector {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &TLSInspector{timeout: timeout}
}

// InspectTLS connects to host:443 and verifies TLS configurations.
func (t *TLSInspector) InspectTLS(ctx context.Context, hostname string) (types.TLSEvidence, error) {
	hostname = strings.TrimSpace(hostname)
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}

	evidence := types.TLSEvidence{
		HTTPS: true,
	}

	if security.IsBlockedHost(hostname) {
		evidence.HTTPS = false
		return evidence, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil || len(ips) == 0 {
		evidence.HTTPS = false
		return evidence, nil
	}

	var safeIP net.IP
	for _, ip := range ips {
		if !security.IsBlockedIP(ip) {
			safeIP = ip
			break
		}
	}
	if safeIP == nil {
		evidence.HTTPS = false
		return evidence, nil
	}

	dialer := &net.Dialer{Timeout: t.timeout}
	conf := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // we want to inspect invalid/self-signed certs rather than failing immediately
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(safeIP.String(), "443"), conf)
	if err != nil {
		evidence.HTTPS = false
		evidence.Valid = false
		return evidence, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		evidence.Valid = false
		return evidence, nil
	}

	cert := state.PeerCertificates[0]
	evidence.Issuer = cert.Issuer.CommonName
	if evidence.Issuer == "" && len(cert.Issuer.Organization) > 0 {
		evidence.Issuer = cert.Issuer.Organization[0]
	}
	evidence.Subject = cert.Subject.CommonName
	evidence.ExpiresAt = cert.NotAfter.Format(time.RFC3339)
	evidence.DaysToExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
	evidence.SANs = cert.DNSNames

	// Check if self-signed
	if cert.Issuer.CommonName == cert.Subject.CommonName && cert.Issuer.CommonName != "" {
		evidence.SelfSigned = true
	}

	// Verify hostname matches SAN / CommonName
	if err := cert.VerifyHostname(hostname); err != nil {
		evidence.HostnameMismatch = true
	}

	// Check validity against system roots
	opts := x509.VerifyOptions{
		DNSName: hostname,
	}
	if _, err := cert.Verify(opts); err == nil && !evidence.HostnameMismatch && time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore) {
		evidence.Valid = true
	} else {
		evidence.Valid = false
	}

	evidence.TLSVersion = tlsVersionToString(state.Version)
	evidence.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	return evidence, nil
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown TLS"
	}
}
