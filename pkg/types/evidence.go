package types

import "time"

// TargetType identifies the category of target under investigation.
type TargetType string

const (
	TargetTypeURL     TargetType = "url"
	TargetTypeWebsite TargetType = "website"
	TargetTypeWallet  TargetType = "wallet"
	TargetTypeMessage TargetType = "message"
	TargetTypeCase    TargetType = "case"
	TargetTypeDomain  TargetType = "domain"
)

// DNSRecord represents a parsed DNS entry.
type DNSRecord struct {
	Type string   `json:"type"`
	TTL  uint32   `json:"ttl,omitempty"`
	Data []string `json:"data"`
}

// DomainEvidence captures registrar, DNS, and hosting footprint.
type DomainEvidence struct {
	Name         string      `json:"name"`
	Subdomain    string      `json:"subdomain,omitempty"`
	TLD          string      `json:"tld"`
	AgeDays      int         `json:"age_days,omitempty"`
	Registrar    string      `json:"registrar,omitempty"`
	CreatedDate  string      `json:"created_date,omitempty"`
	ExpiresDate  string      `json:"expires_date,omitempty"`
	Nameservers  []string    `json:"nameservers,omitempty"`
	DNSRecords   []DNSRecord `json:"dns_records,omitempty"`
	IPAddresses  []string    `json:"ip_addresses,omitempty"`
	ASN          string      `json:"asn,omitempty"`
	HostingOrg   string      `json:"hosting_org,omitempty"`
	Country      string      `json:"country,omitempty"`
	Punycode     bool        `json:"punycode"`
	Homoglyph    bool        `json:"homoglyph"`
	IsDynamicDNS bool        `json:"is_dynamic_dns"`
}

// TLSEvidence captures certificate and cryptographic configuration.
type TLSEvidence struct {
	HTTPS            bool     `json:"https"`
	Valid            bool     `json:"valid"`
	Issuer           string   `json:"issuer,omitempty"`
	Subject          string   `json:"subject,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
	DaysToExpiry     int      `json:"days_to_expiry,omitempty"`
	HostnameMismatch bool     `json:"hostname_mismatch"`
	SelfSigned       bool     `json:"self_signed"`
	SANs             []string `json:"sans,omitempty"`
	TLSVersion       string   `json:"tls_version,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
}

// URLStructureEvidence captures URI parsing heuristics and anomalies.
type URLStructureEvidence struct {
	SuspiciousChars     bool     `json:"suspicious_chars"`
	ExcessiveSubdomains bool     `json:"excessive_subdomains"`
	SuspiciousPath      bool     `json:"suspicious_path"`
	URLEncoded          bool     `json:"url_encoded"`
	IPHost              bool     `json:"ip_host"`
	ShortenedURL        bool     `json:"shortened_url"`
	SuspiciousParams    []string `json:"suspicious_params,omitempty"`
	LookalikeTarget     string   `json:"lookalike_target,omitempty"`
	EmbeddedCredentials bool     `json:"embedded_credentials"`
	DoubleExtension     bool     `json:"double_extension"`
}

// RedirectHop represents a single hop in a redirect chain.
type RedirectHop struct {
	FromURL    string `json:"from_url"`
	ToURL      string `json:"to_url"`
	StatusCode int    `json:"status_code"`
	IP         string `json:"ip,omitempty"`
}

// RedirectEvidence captures redirect behaviors.
type RedirectEvidence struct {
	Count                  int           `json:"count"`
	Chain                  []RedirectHop `json:"chain"`
	FinalDestination       string        `json:"final_destination"`
	CrossDomain            bool          `json:"cross_domain"`
	SuspiciousDestinations []string      `json:"suspicious_destinations,omitempty"`
}

// ScriptEvidence details an external or suspicious script.
type ScriptEvidence struct {
	Source     string `json:"source"`
	Suspicious bool   `json:"suspicious"`
	Reason     string `json:"reason,omitempty"`
}

// WebsiteEvidence captures passive/sandboxed inspection of webpage contents.
type WebsiteEvidence struct {
	Title                 string           `json:"title,omitempty"`
	MetaDescription       string           `json:"meta_description,omitempty"`
	LoginForm             bool             `json:"login_form"`
	PasswordField         bool             `json:"password_field"`
	WalletConnection      bool             `json:"wallet_connection"`
	CryptoKeywords        []string         `json:"crypto_keywords,omitempty"`
	Downloads             bool             `json:"downloads"`
	DownloadLinks         []string         `json:"download_links,omitempty"`
	ExternalScripts       []string         `json:"external_scripts,omitempty"`
	SuspiciousScripts     []ScriptEvidence `json:"suspicious_scripts,omitempty"`
	IframeUsage           bool             `json:"iframe_usage"`
	IframeSources         []string         `json:"iframe_sources,omitempty"`
	ObfuscatedJavaScript  bool             `json:"obfuscated_javascript"`
	SuspiciousForms       []string         `json:"suspicious_forms,omitempty"`
	BrandImpersonation    string           `json:"brand_impersonation,omitempty"`
	UnexpectedExternalRes []string         `json:"unexpected_external_resources,omitempty"`
	ContentHash           string           `json:"content_hash,omitempty"`
	ExtractedWallets      []string         `json:"extracted_wallets,omitempty"`
	ExtractedContracts    []string         `json:"extracted_contracts,omitempty"`
}

// ThreatIntelligenceEvidence aggregates signals from threat intel sources.
type ThreatIntelligenceEvidence struct {
	Phishing            bool     `json:"phishing"`
	Malware             bool     `json:"malware"`
	Reputation          string   `json:"reputation"` // "clean", "suspicious", "malicious", "unknown"
	MaliciousReports    int      `json:"malicious_reports"`
	TotalEngines        int      `json:"total_engines"`
	KnownScamIndicators []string `json:"known_scam_indicators,omitempty"`
	ThreatFeeds         []string `json:"threat_feeds,omitempty"`
	SecurityLabels      []string `json:"security_labels,omitempty"`
}

// URLEvidence is the structured evidence bundle for a URL/website.
type URLEvidence struct {
	TargetType         TargetType                 `json:"target_type"`
	Target             string                     `json:"target"`
	NormalizedURL      string                     `json:"normalized_url"`
	Domain             DomainEvidence             `json:"domain"`
	TLS                TLSEvidence                `json:"tls"`
	URLStructure       URLStructureEvidence       `json:"url_structure"`
	Redirects          RedirectEvidence           `json:"redirects"`
	Website            WebsiteEvidence            `json:"website"`
	ThreatIntelligence ThreatIntelligenceEvidence `json:"threat_intelligence"`
	CollectedAt        time.Time                  `json:"collected_at"`
	ExecutionTimeMs    int64                      `json:"execution_time_ms"`
}

// TokenHolding represents a token balance for a wallet.
type TokenHolding struct {
	TokenAddress string  `json:"token_address"`
	Symbol       string  `json:"symbol"`
	Balance      string  `json:"balance"`
	Decimals     int     `json:"decimals"`
	USDValue     float64 `json:"usd_value,omitempty"`
}

// WalletActivityEvidence tracks behavioral volume and timing.
type WalletActivityEvidence struct {
	IncomingTransactions int     `json:"incoming_transactions"`
	OutgoingTransactions int     `json:"outgoing_transactions"`
	TransactionFrequency float64 `json:"tx_frequency_per_day"`
	RapidFundMovement    bool    `json:"rapid_fund_movement"`
	LargeTransfers       bool    `json:"large_transfers"`
	DormantBurstActivity bool    `json:"dormant_burst_activity"`
}

// ContractInteractionEvidence tracks smart contract relationships.
type ContractInteractionEvidence struct {
	InteractedCount      int      `json:"interacted"`
	KnownMaliciousCount  int      `json:"known_malicious"`
	HighRiskCount        int      `json:"high_risk"`
	UnlimitedApprovals   int      `json:"unlimited_approvals"`
	InteractedContracts  []string `json:"interacted_contracts,omitempty"`
	SuspiciousApprovals  []string `json:"suspicious_approvals,omitempty"`
	KnownDrainerContract bool     `json:"known_drainer_contract"`
}

// CounterpartyEvidence tracks risky peer interactions.
type CounterpartyEvidence struct {
	KnownRiskyCount      int      `json:"known_risky"`
	MixerExposure        bool     `json:"mixer_exposure"`
	MixerProtocols       []string `json:"mixer_protocols,omitempty"`
	PhishingCounterparty bool     `json:"phishing_counterparty"`
	HighRiskCounterparts []string `json:"high_risk_counterparts,omitempty"`
}

// FundFlowEvidence tracks movement patterns.
type FundFlowEvidence struct {
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	LayeringDetected     bool     `json:"layering_detected"`
	DispersalDetected    bool     `json:"dispersal_detected"`
}

// WalletSummaryInfo represents static blockchain metadata.
type WalletSummaryInfo struct {
	Address          string         `json:"address"`
	Network          string         `json:"network"`
	Balance          string         `json:"balance"`
	BalanceUSD       float64        `json:"balance_usd,omitempty"`
	TransactionCount int64          `json:"transaction_count"`
	FirstSeen        string         `json:"first_seen,omitempty"`
	LastSeen         string         `json:"last_seen,omitempty"`
	TokenHoldings    []TokenHolding `json:"token_holdings,omitempty"`
	IsContract       bool           `json:"is_contract"`
}

// WalletEvidence is the structured evidence bundle for a blockchain wallet.
type WalletEvidence struct {
	TargetType         TargetType                  `json:"target_type"`
	Network            string                      `json:"network"`
	Address            string                      `json:"address"`
	NormalizedAddress  string                      `json:"normalized_address"`
	Wallet             WalletSummaryInfo           `json:"wallet"`
	Activity           WalletActivityEvidence      `json:"activity"`
	Contracts          ContractInteractionEvidence `json:"contracts"`
	Counterparties     CounterpartyEvidence        `json:"counterparties"`
	FundFlow           FundFlowEvidence            `json:"fund_flow"`
	ThreatIntelligence ThreatIntelligenceEvidence  `json:"threat_intelligence"`
	CollectedAt        time.Time                   `json:"collected_at"`
	ExecutionTimeMs    int64                       `json:"execution_time_ms"`
}

// MessageAnalysisSignals captures NLP/heuristic signals.
type MessageAnalysisSignals struct {
	Urgency            bool     `json:"urgency"`
	Impersonation      bool     `json:"impersonation"`
	CryptoReward       bool     `json:"crypto_reward"`
	CredentialRequest  bool     `json:"credential_request"`
	FearTactics        bool     `json:"fear_tactics"`
	FakeGiveaway       bool     `json:"fake_giveaway"`
	MaliciousLinks     bool     `json:"malicious_links"`
	SeedPhraseRequest  bool     `json:"seed_phrase_request"`
	MoneyRequest       bool     `json:"money_request"`
	FakeSupport        bool     `json:"fake_support"`
	DrainerTechnique   bool     `json:"drainer_technique"`
	DetectedKeywords   []string `json:"detected_keywords,omitempty"`
	ImpersonatedBrands []string `json:"impersonated_brands,omitempty"`
}

// ExtractedEntities holds entities found in text or code.
type ExtractedEntities struct {
	URLs              []string `json:"urls,omitempty"`
	WalletAddresses   []string `json:"wallet_addresses,omitempty"`
	Domains           []string `json:"domains,omitempty"`
	Usernames         []string `json:"usernames,omitempty"`
	EmailAddresses    []string `json:"email_addresses,omitempty"`
	PhoneNumbers      []string `json:"phone_numbers,omitempty"`
	TransactionHashes []string `json:"transaction_hashes,omitempty"`
	ContractAddresses []string `json:"contract_addresses,omitempty"`
}

// MessageEvidence is the structured evidence bundle for a text/chat message.
type MessageEvidence struct {
	TargetType        TargetType             `json:"target_type"`
	MessageSource     string                 `json:"message_source"` // telegram, whatsapp, discord, sms, email, twitter, arbitrary
	MessageLength     int                    `json:"message_length"`
	MessageHash       string                 `json:"message_hash"`
	MessageAnalysis   MessageAnalysisSignals `json:"message_analysis"`
	ExtractedEntities ExtractedEntities      `json:"extracted_entities"`
	CollectedAt       time.Time              `json:"collected_at"`
	ExecutionTimeMs   int64                  `json:"execution_time_ms"`
}

// TargetRelationship represents an edge in the investigation entity graph.
type TargetRelationship struct {
	SourceTarget string `json:"source_target"`
	SourceType   string `json:"source_type"`
	RelationType string `json:"relation_type"` // e.g. "extracted_from", "connected_to", "redirects_to", "interacts_with"
	TargetTarget string `json:"target_target"`
	TargetType   string `json:"target_type"`
	Details      string `json:"details,omitempty"`
}

// UnifiedInvestigationEvidence aggregates all collected evidence for the AI Security Analyst.
type UnifiedInvestigationEvidence struct {
	InvestigationID string                     `json:"investigation_id"`
	CaseID          string                     `json:"case_id"`
	TargetType      TargetType                 `json:"target_type"`
	Target          string                     `json:"target"`
	CollectedAt     time.Time                  `json:"collected_at"`
	URLEvidence     *URLEvidence               `json:"url_evidence,omitempty"`
	WalletEvidence  *WalletEvidence            `json:"wallet_evidence,omitempty"`
	MessageEvidence *MessageEvidence           `json:"message_evidence,omitempty"`
	ThreatIntel     ThreatIntelligenceEvidence `json:"threat_intelligence"`
	Relationships   []TargetRelationship       `json:"relationships,omitempty"`
	AuditMetadata   map[string]any             `json:"audit_metadata,omitempty"`
}
