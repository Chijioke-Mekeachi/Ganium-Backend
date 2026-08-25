package walletanalyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"ganium/pkg/types"
)

var evmAddressRegex = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// EVMDriver handles Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche.
type EVMDriver struct {
	network string
	rpcURL  string
}

func NewEVMDriver(network, rpcURL string) *EVMDriver {
	return &EVMDriver{
		network: strings.ToLower(network),
		rpcURL:  rpcURL,
	}
}

func (d *EVMDriver) ValidateAddress(address string) bool {
	return evmAddressRegex.MatchString(strings.TrimSpace(address))
}

func (d *EVMDriver) FetchWalletEvidence(ctx context.Context, address string) (*types.WalletEvidence, error) {
	trimmed := strings.TrimSpace(address)
	if !d.ValidateAddress(trimmed) {
		return nil, fmt.Errorf("invalid %s EVM address format: %s", d.network, address)
	}

	normalized := strings.ToLower(trimmed)

	// Build structured EVM evidence
	evidence := &types.WalletEvidence{
		TargetType:        types.TargetTypeWallet,
		Network:           d.network,
		Address:           trimmed,
		NormalizedAddress: normalized,
		CollectedAt:       time.Now().UTC(),
		Wallet: types.WalletSummaryInfo{
			Address:          normalized,
			Network:          d.network,
			Balance:          "0.00",
			TransactionCount: 0,
		},
		Activity: types.WalletActivityEvidence{
			IncomingTransactions: 0,
			OutgoingTransactions: 0,
			TransactionFrequency: 0.0,
		},
		Contracts: types.ContractInteractionEvidence{
			InteractedCount:     0,
			KnownMaliciousCount: 0,
			HighRiskCount:       0,
			UnlimitedApprovals:  0,
		},
		Counterparties: types.CounterpartyEvidence{
			KnownRiskyCount: 0,
			MixerExposure:   false,
		},
		FundFlow: types.FundFlowEvidence{
			LayeringDetected:  false,
			DispersalDetected: false,
		},
	}

	return evidence, nil
}
