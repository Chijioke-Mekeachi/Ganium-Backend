package urlanalyzer

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"ganium/internal/sandbox"
	"ganium/pkg/types"
)

var (
	shortenerDomains = map[string]struct{}{
		"bit.ly": {}, "tinyurl.com": {}, "t.co": {}, "is.gd": {}, "buff.ly": {}, "ow.ly": {}, "cutt.ly": {}, "rb.gy": {},
	}

	popularBrands = []string{
		"binance", "metamask", "coinbase", "uniswap", "opensea", "phantom", "ledger",
		"trustwallet", "kraken", "bybit", "okx", "paypal", "google", "apple", "microsoft", "telegram",
	}

	walletConnectionSignatures = []string{
		"window.ethereum", "ethereum.request", "eth_requestaccounts", "personal_sign",
		"eth_signtypeddata", "walletconnect", "wagmi", "@web3modal", "solana.connect",
		"solana.signmessage", "phantom.solana", "injectedconnector",
	}

	drainerSignatures = []string{
		"msdrainer", "infernodrainer", "pinkdrainer", "angeldrainer", "monkeydrainer",
		"claimreward", "claimairdrop", "permit2", "setapprovalforall",
	}

	cryptoKeywordsList = []string{
		"usdt", "usdc", "bitcoin", "ethereum", "solana", "airdrop", "presale", "token claim",
		"staking rewards", "connect wallet", "mint now", "free mint", "drainer", "private key",
		"seed phrase", "100x gem", "guaranteed profit",
	}

	obfuscationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)`), // Dean Edwards packer
		regexp.MustCompile(`(?i)_0x[a-f0-9]{4,8}`), // Obfuscator.io hex identifiers
		regexp.MustCompile(`(?i)unescape\s*\(\s*['"][%0-9a-f]{20,}`),
		regexp.MustCompile(`(?i)String\.fromCharCode\s*\(\s*(\d+\s*,\s*){8,}`),
	}

	walletAddressRegex = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	solanaAddressRegex = regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`)
)

// AnalyzeURLStructure evaluates structural indicators of a URL.
func AnalyzeURLStructure(parsed *url.URL) types.URLStructureEvidence {
	var evidence types.URLStructureEvidence

	host := parsed.Hostname()
	fullURL := parsed.String()

	// Check if IP Host
	if ip := net.ParseIP(host); ip != nil {
		evidence.IPHost = true
	}

	// Check Shortener
	if _, ok := shortenerDomains[strings.ToLower(host)]; ok {
		evidence.ShortenedURL = true
	}

	// Check excessive subdomains
	parts := strings.Split(host, ".")
	if len(parts) > 3 {
		evidence.ExcessiveSubdomains = true
	}

	// Check lookalike target
	hostLower := strings.ToLower(host)
	for _, brand := range popularBrands {
		if strings.Contains(hostLower, brand) && !isOfficialDomain(hostLower, brand) {
			evidence.LookalikeTarget = brand
			break
		}
	}

	// Check URL-encoded characters in path
	if strings.Contains(parsed.RawPath, "%") || strings.Contains(parsed.Path, "%") {
		evidence.URLEncoded = true
	}

	// Check suspicious characters
	if strings.Contains(fullURL, "@") || strings.Contains(fullURL, "..") {
		evidence.SuspiciousChars = true
	}
	if parsed.User != nil {
		evidence.EmbeddedCredentials = true
	}

	// Check double extension in path
	pathLower := strings.ToLower(parsed.Path)
	if strings.HasSuffix(pathLower, ".exe.zip") || strings.HasSuffix(pathLower, ".pdf.exe") || strings.HasSuffix(pathLower, ".html.js") {
		evidence.DoubleExtension = true
	}

	// Suspicious query parameters
	suspiciousQueryKeys := []string{"redirect", "return_url", "dest", "wallet", "token", "claim", "seed", "key"}
	q := parsed.Query()
	for _, k := range suspiciousQueryKeys {
		if q.Get(k) != "" {
			evidence.SuspiciousParams = append(evidence.SuspiciousParams, k)
		}
	}

	return evidence
}

// AnalyzeWebsiteContent extracts features from sandbox HTML output.
func AnalyzeWebsiteContent(res *sandbox.SandboxResult) types.WebsiteEvidence {
	if res == nil {
		return types.WebsiteEvidence{}
	}

	var evidence types.WebsiteEvidence
	evidence.Title = res.Title
	evidence.MetaDescription = res.MetaDescription
	evidence.ContentHash = fmtHash(res.HTMLBody)

	bodyLower := strings.ToLower(res.HTMLBody)

	// Check Login & Password fields
	if strings.Contains(bodyLower, "type=\"password\"") || strings.Contains(bodyLower, "type='password'") {
		evidence.PasswordField = true
		evidence.LoginForm = true
	}
	if strings.Contains(bodyLower, "login") || strings.Contains(bodyLower, "sign in") || strings.Contains(bodyLower, "log in") {
		evidence.LoginForm = true
	}

	// Check Web3 Wallet Connection functionality
	for _, sig := range walletConnectionSignatures {
		if strings.Contains(bodyLower, sig) {
			evidence.WalletConnection = true
			break
		}
	}

	// Check Crypto Keywords
	for _, kw := range cryptoKeywordsList {
		if strings.Contains(bodyLower, kw) {
			evidence.CryptoKeywords = append(evidence.CryptoKeywords, kw)
		}
	}

	// Check Downloads
	for _, link := range res.LinksFound {
		linkLower := strings.ToLower(link)
		if strings.HasSuffix(linkLower, ".exe") || strings.HasSuffix(linkLower, ".dmg") ||
			strings.HasSuffix(linkLower, ".apk") || strings.HasSuffix(linkLower, ".zip") ||
			strings.HasSuffix(linkLower, ".tar.gz") {
			evidence.Downloads = true
			evidence.DownloadLinks = append(evidence.DownloadLinks, link)
		}
	}

	// Check External and Suspicious Scripts
	for _, src := range res.ScriptsFound {
		evidence.ExternalScripts = append(evidence.ExternalScripts, src)
		srcLower := strings.ToLower(src)
		for _, drainer := range drainerSignatures {
			if strings.Contains(srcLower, drainer) {
				evidence.SuspiciousScripts = append(evidence.SuspiciousScripts, types.ScriptEvidence{
					Source:     src,
					Suspicious: true,
					Reason:     "Script URL matches known drainer signature: " + drainer,
				})
			}
		}
	}

	// Check Iframes
	if strings.Contains(bodyLower, "<iframe") {
		evidence.IframeUsage = true
	}

	// Check Obfuscated JS
	for _, pattern := range obfuscationPatterns {
		if pattern.MatchString(res.HTMLBody) {
			evidence.ObfuscatedJavaScript = true
			break
		}
	}

	// Check Brand Impersonation
	for _, brand := range popularBrands {
		if strings.Contains(strings.ToLower(res.Title), brand) {
			evidence.BrandImpersonation = brand
			break
		}
	}

	// Extract Wallets & Contracts
	wallets := walletAddressRegex.FindAllString(res.HTMLBody, 10)
	evidence.ExtractedWallets = uniqueStrings(wallets)

	return evidence
}

func isOfficialDomain(host, brand string) bool {
	official := map[string][]string{
		"binance":     {"binance.com", "binance.org", "binance.us", "binance.vision"},
		"coinbase":    {"coinbase.com"},
		"metamask":    {"metamask.io"},
		"uniswap":     {"uniswap.org", "uniswap.exchange"},
		"opensea":     {"opensea.io"},
		"phantom":     {"phantom.app"},
		"ledger":      {"ledger.com"},
		"paypal":      {"paypal.com"},
		"google":      {"google.com"},
		"apple":       {"apple.com"},
		"microsoft":   {"microsoft.com"},
		"trustwallet": {"trustwallet.com"},
	}

	allowedHosts, exists := official[brand]
	if !exists {
		return false
	}

	for _, allowed := range allowedHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func fmtHash(s string) string {
	if len(s) == 0 {
		return ""
	}
	if len(s) > 32 {
		return s[:32]
	}
	return s
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]struct{})
	var res []string
	for _, s := range slice {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			res = append(res, s)
		}
	}
	return res
}
