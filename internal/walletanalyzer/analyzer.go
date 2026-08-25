package walletanalyzer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"ganium/internal/threatintel"
	"ganium/pkg/types"
)

// ChainDriver defines the contract for an individual blockchain network driver.
type ChainDriver interface {
	ValidateAddress(address string) bool
	FetchWalletEvidence(ctx context.Context, address string) (*types.WalletEvidence, error)
}

// WalletAnalyzer defines the contract for wallet address investigations.
type WalletAnalyzer interface {
	Analyze(ctx context.Context, network string, address string) (*types.WalletEvidence, error)
}

// Analyzer orchestrates multi-chain drivers and threat intelligence enrichment.
type Analyzer struct {
	drivers     map[string]ChainDriver
	threatIntel *threatintel.Aggregator
}

func NewAnalyzer(threatIntel *threatintel.Aggregator, solanaRPC, ethRPC string) *Analyzer {
	drivers := map[string]ChainDriver{
		"ethereum": NewEVMDriver("ethereum", ethRPC),
		"eth":      NewEVMDriver("ethereum", ethRPC),
		"bsc":      NewEVMDriver("bsc", "https://bsc-dataseed.binance.org"),
		"polygon":  NewEVMDriver("polygon", "https://polygon-rpc.com"),
		"arbitrum": NewEVMDriver("arbitrum", "https://arb1.arbitrum.io/rpc"),
		"optimism": NewEVMDriver("optimism", "https://mainnet.optimism.io"),
		"base":     NewEVMDriver("base", "https://mainnet.base.org"),
		"solana":   NewSolanaDriver(solanaRPC),
		"sol":      NewSolanaDriver(solanaRPC),
		"bitcoin":  NewBitcoinDriver(),
		"btc":      NewBitcoinDriver(),
	}

	return &Analyzer{
		drivers:     drivers,
		threatIntel: threatIntel,
	}
}

// RegisterDriver allows dynamic extension for new blockchains.
func (a *Analyzer) RegisterDriver(network string, driver ChainDriver) {
	a.drivers[strings.ToLower(network)] = driver
}

// Analyze validates the network, runs chain-specific driver extraction, and aggregates threat intelligence.
func (a *Analyzer) Analyze(ctx context.Context, network string, address string) (*types.WalletEvidence, error) {
	startTime := time.Now()
	trimmedAddr := strings.TrimSpace(address)
	if trimmedAddr == "" {
		return nil, errors.New("wallet address cannot be empty")
	}

	netKey := strings.ToLower(strings.TrimSpace(network))
	if netKey == "" || netKey == "auto" {
		netKey = a.detectNetwork(trimmedAddr)
	}

	driver, exists := a.drivers[netKey]
	if !exists {
		return nil, fmt.Errorf("unsupported blockchain network: %s", network)
	}

	evidence, err := driver.FetchWalletEvidence(ctx, trimmedAddr)
	if err != nil {
		return nil, err
	}

	// Threat Intelligence Enrichment
	if a.threatIntel != nil {
		evidence.ThreatIntelligence = a.threatIntel.CheckWallet(ctx, netKey, trimmedAddr)
	}

	evidence.ExecutionTimeMs = time.Since(startTime).Milliseconds()
	return evidence, nil
}

func (a *Analyzer) detectNetwork(address string) string {
	if strings.HasPrefix(address, "0x") && len(address) == 42 {
		return "ethereum"
	}
	if strings.HasPrefix(address, "bc1") || strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") {
		return "bitcoin"
	}
	if len(address) >= 32 && len(address) <= 44 {
		return "solana"
	}
	return "ethereum"
}
