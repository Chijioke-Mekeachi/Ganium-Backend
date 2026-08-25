package urlanalyzer

import (
	"net/url"
	"testing"

	"ganium/internal/sandbox"
)

func TestDetectHomoglyphs(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", false},
		{"pаypal.com", true}, // 'а' is Cyrillic small letter a (U+0430)
		{"binance.com", false},
		{"bіnance.com", true}, // 'і' is Cyrillic small letter byelorussian-ukrainian i (U+0456)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res := DetectHomoglyphs(tt.input)
			if res != tt.expected {
				t.Errorf("DetectHomoglyphs(%q) = %v; want %v", tt.input, res, tt.expected)
			}
		})
	}
}

func TestAnalyzeURLStructure(t *testing.T) {
	u, _ := url.Parse("https://metamask-verify.fake-site.com/login?claim=1&redirect=https://other.com")
	evidence := AnalyzeURLStructure(u)

	if evidence.LookalikeTarget != "metamask" {
		t.Errorf("Expected lookalike target 'metamask', got %s", evidence.LookalikeTarget)
	}
	if len(evidence.SuspiciousParams) == 0 {
		t.Errorf("Expected suspicious params detected")
	}
}

func TestAnalyzeWebsiteContent(t *testing.T) {
	mockHTML := `
	<!DOCTYPE html>
	<html>
	<head><title>MetaMask AirDrop Claim</title></head>
	<body>
		<h1>Claim Free 500 USDT</h1>
		<form action="/auth"><input type="password" name="seed"/></form>
		<script src="https://cdn.example.com/msdrainer.js"></script>
		<script>
			window.ethereum.request({ method: 'eth_requestAccounts' });
		</script>
	</body>
	</html>
	`
	sandRes := &sandbox.SandboxResult{
		Title:        "MetaMask AirDrop Claim",
		HTMLBody:     mockHTML,
		ScriptsFound: []string{"https://cdn.example.com/msdrainer.js"},
		FormsFound:   []string{"/auth"},
	}

	evidence := AnalyzeWebsiteContent(sandRes)
	if !evidence.LoginForm {
		t.Errorf("Expected LoginForm = true")
	}
	if !evidence.PasswordField {
		t.Errorf("Expected PasswordField = true")
	}
	if !evidence.WalletConnection {
		t.Errorf("Expected WalletConnection = true")
	}
	if len(evidence.SuspiciousScripts) == 0 {
		t.Errorf("Expected drainer script detected in SuspiciousScripts")
	}
	if evidence.BrandImpersonation != "metamask" {
		t.Errorf("Expected BrandImpersonation 'metamask', got %s", evidence.BrandImpersonation)
	}
}
