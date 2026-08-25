package messageanalyzer

import (
	"net/url"
	"regexp"
	"strings"

	"ganium/pkg/types"
)

var (
	// Entity extraction regexes
	urlPattern          = regexp.MustCompile(`(?i)\b(https?://|hxxps?://)[^\s<>"'{}|\\^` + "`" + `]+`)
	rawDomainPattern    = regexp.MustCompile(`(?i)\b[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(com|org|net|xyz|top|cc|io|app|dev|me|info|live|vip|site|online|space|store|tech|co)\b`)
	evmAddressPattern   = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	solanaAddressPattern= regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`)
	btcAddressPattern   = regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b`)
	txHashPattern       = regexp.MustCompile(`\b0x[a-fA-F0-9]{64}\b`)
	emailPattern        = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	usernamePattern     = regexp.MustCompile(`\B@[a-zA-Z0-9_]{3,32}\b`)
	phonePattern        = regexp.MustCompile(`(\+?\d{1,3}[-.\s]?)?(\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b`)
)

// ExtractEntities finds URLs, wallets, domains, emails, and handles inside text.
func ExtractEntities(text string) types.ExtractedEntities {
	var entities types.ExtractedEntities

	// 1. URLs
	foundURLs := urlPattern.FindAllString(text, 50)
	for _, u := range foundURLs {
		clean := strings.Replace(u, "hxxp://", "http://", 1)
		clean = strings.Replace(clean, "hxxps://", "https://", 1)
		clean = strings.TrimRight(clean, ".,!?;:)]}")
		entities.URLs = append(entities.URLs, clean)
	}
	entities.URLs = unique(entities.URLs)

	// 2. Raw Domains
	foundDomains := rawDomainPattern.FindAllString(text, 50)
	for _, d := range foundDomains {
		dClean := strings.ToLower(strings.TrimRight(d, ".,!?;:)]}"))
		entities.Domains = append(entities.Domains, dClean)
	}
	// Also extract domains from found URLs
	for _, u := range entities.URLs {
		if parsed, err := url.Parse(u); err == nil && parsed.Hostname() != "" {
			entities.Domains = append(entities.Domains, strings.ToLower(parsed.Hostname()))
		}
	}
	entities.Domains = unique(entities.Domains)

	// 3. EVM Wallets & Contracts
	evmAddresses := evmAddressPattern.FindAllString(text, 50)
	entities.WalletAddresses = append(entities.WalletAddresses, evmAddresses...)

	// 4. Solana Wallets (filtered to avoid matching plain dictionary words)
	solAddresses := solanaAddressPattern.FindAllString(text, 50)
	for _, sol := range solAddresses {
		if len(sol) >= 32 && isLikelyCryptoBase58(sol) {
			entities.WalletAddresses = append(entities.WalletAddresses, sol)
		}
	}

	// 5. Bitcoin Addresses
	btcAddresses := btcAddressPattern.FindAllString(text, 50)
	entities.WalletAddresses = append(entities.WalletAddresses, btcAddresses...)
	entities.WalletAddresses = unique(entities.WalletAddresses)

	// 6. Transaction Hashes
	txHashes := txHashPattern.FindAllString(text, 20)
	entities.TransactionHashes = unique(txHashes)

	// 7. Emails
	emails := emailPattern.FindAllString(text, 20)
	entities.EmailAddresses = unique(emails)

	// 8. Usernames
	usernames := usernamePattern.FindAllString(text, 20)
	entities.Usernames = unique(usernames)

	return entities
}

func isLikelyCryptoBase58(s string) bool {
	// A valid base58 address contains a mix of digits and uppercase/lowercase letters
	var hasDigit, hasUpper, hasLower bool
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		} else if r >= 'A' && r <= 'Z' {
			hasUpper = true
		} else if r >= 'a' && r <= 'z' {
			hasLower = true
		}
	}
	return (hasDigit && hasUpper) || (hasUpper && hasLower)
}

func unique(slice []string) []string {
	seen := make(map[string]struct{})
	var res []string
	for _, s := range slice {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			res = append(res, s)
		}
	}
	return res
}
