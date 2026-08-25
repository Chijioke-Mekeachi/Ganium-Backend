package security

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip       string
		expected bool
		desc     string
	}{
		{"127.0.0.1", true, "Loopback IPv4"},
		{"127.10.20.30", true, "Loopback IPv4 range"},
		{"::1", true, "Loopback IPv6"},
		{"10.0.0.1", true, "RFC1918 Class A"},
		{"172.16.5.10", true, "RFC1918 Class B"},
		{"192.168.1.254", true, "RFC1918 Class C"},
		{"169.254.169.254", true, "AWS/GCP/Azure Metadata"},
		{"100.100.100.200", true, "Alibaba Cloud Metadata"},
		{"100.64.0.1", true, "Carrier Grade NAT"},
		{"224.0.0.1", true, "Multicast"},
		{"0.0.0.0", true, "Unspecified IPv4"},
		{"::", true, "Unspecified IPv6"},
		{"fe80::1", true, "Link-local IPv6"},
		{"fc00::1", true, "ULA IPv6"},
		{"8.8.8.8", false, "Public Google DNS"},
		{"1.1.1.1", false, "Public Cloudflare DNS"},
		{"93.184.216.34", false, "Public example.com"},
		{"2606:4700:4700::1111", false, "Public Cloudflare IPv6"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			parsed := net.ParseIP(tc.ip)
			if parsed == nil {
				t.Fatalf("failed to parse test IP: %s", tc.ip)
			}
			result := IsBlockedIP(parsed)
			if result != tc.expected {
				t.Errorf("IsBlockedIP(%s) = %v; want %v (%s)", tc.ip, result, tc.expected, tc.desc)
			}
		})
	}
}

func TestIsBlockedHost(t *testing.T) {
	cases := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"sub.localhost", true},
		{"metadata.google.internal", true},
		{"instance-data", true},
		{"router.local", true},
		{"server.internal", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true},
		{"example.com", false},
		{"google.com", false},
		{"ethereum.org", false},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			res := IsBlockedHost(tc.host)
			if res != tc.expected {
				t.Errorf("IsBlockedHost(%s) = %v; want %v", tc.host, res, tc.expected)
			}
		})
	}
}

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		rawURL  string
		wantErr bool
	}{
		{"https://example.com", false},
		{"http://test.ganium.org/path?q=1", false},
		{"ftp://example.com/file", true},
		{"file:///etc/passwd", true},
		{"gopher://127.0.0.1:70", true},
		{"http://127.0.0.1/admin", true},
		{"http://localhost:8080", true},
		{"http://169.254.169.254/latest/meta-data/", true},
		{"javascript:alert(1)", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			_, err := ValidateTargetURL(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTargetURL(%q) err = %v, wantErr %v", tt.rawURL, err, tt.wantErr)
			}
		})
	}
}
