package walletanalyzer

import (
	"context"
	"testing"

	"ganium/internal/threatintel"
)

func TestWalletAnalyzerValidationAndDispatch(t *testing.T) {
	mockTI := threatintel.NewAggregator(nil, &threatintel.MockProvider{})
	analyzer := NewAnalyzer(mockTI, "https://api.mainnet-beta.solana.com", "https://cloudflare-eth.com")

	ctx := context.Background()

	// 1. Valid Ethereum Address
	ethAddr := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	ethEvidence, err := analyzer.Analyze(ctx, "ethereum", ethAddr)
	if err != nil {
		t.Fatalf("Failed to analyze valid EVM address: %v", err)
	}
	if ethEvidence.Network != "ethereum" || ethEvidence.NormalizedAddress != ethAddr {
		t.Errorf("Unexpected EVM evidence: %+v", ethEvidence)
	}

	// 2. Invalid EVM Address
	_, err = analyzer.Analyze(ctx, "ethereum", "0xinvalid123")
	if err == nil {
		t.Errorf("Expected error for invalid EVM address, got nil")
	}

	// 3. Valid Solana Address
	solAddr := "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" // USDC mint on Solana
	solEvidence, err := analyzer.Analyze(ctx, "solana", solAddr)
	if err != nil {
		t.Fatalf("Failed to analyze valid Solana address: %v", err)
	}
	if solEvidence.Network != "solana" {
		t.Errorf("Expected Solana network, got %s", solEvidence.Network)
	}

	// 4. Auto-detection for Bitcoin
	btcAddr := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	btcEvidence, err := analyzer.Analyze(ctx, "auto", btcAddr)
	if err != nil {
		t.Fatalf("Failed to auto-detect and analyze Bitcoin address: %v", err)
	}
	if btcEvidence.Network != "bitcoin" {
		t.Errorf("Expected bitcoin network auto-detected, got %s", btcEvidence.Network)
	}
}
