package walletanalyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"ganium/pkg/types"
)

var solanaAddressRegex = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)

// SolanaDriver handles Solana network wallet investigations.
type SolanaDriver struct {
	rpcURL string
}

func NewSolanaDriver(rpcURL string) *SolanaDriver {
	return &SolanaDriver{rpcURL: rpcURL}
}

func (d *SolanaDriver) ValidateAddress(address string) bool {
	trimmed := strings.TrimSpace(address)
	return solanaAddressRegex.MatchString(trimmed)
}

func (d *SolanaDriver) FetchWalletEvidence(ctx context.Context, address string) (*types.WalletEvidence, error) {
	trimmed := strings.TrimSpace(address)
	if !d.ValidateAddress(trimmed) {
		return nil, fmt.Errorf("invalid Solana address format: %s", address)
	}

	evidence := &types.WalletEvidence{
		TargetType:        types.TargetTypeWallet,
		Network:           "solana",
		Address:           trimmed,
		NormalizedAddress: trimmed,
		CollectedAt:       time.Now().UTC(),
		Wallet: types.WalletSummaryInfo{
			Address:          trimmed,
			Network:          "solana",
			Balance:          "0.00",
			TransactionCount: 0,
		},
		Activity: types.WalletActivityEvidence{
			IncomingTransactions: 0,
			OutgoingTransactions: 0,
			TransactionFrequency: 0.0,
		},
		Contracts: types.ContractInteractionEvidence{
			InteractedCount: 0,
		},
		Counterparties: types.CounterpartyEvidence{
			KnownRiskyCount: 0,
		},
		FundFlow: types.FundFlowEvidence{},
	}

	return evidence, nil
}
