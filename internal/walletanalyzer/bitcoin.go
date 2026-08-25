package walletanalyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"ganium/pkg/types"
)

var (
	btcLegacyRegex = regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`)
	btcSegwitRegex = regexp.MustCompile(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$`)
)

// BitcoinDriver handles Bitcoin addresses (Legacy P2PKH, P2SH, and Bech32 SegWit).
type BitcoinDriver struct{}

func NewBitcoinDriver() *BitcoinDriver {
	return &BitcoinDriver{}
}

func (d *BitcoinDriver) ValidateAddress(address string) bool {
	trimmed := strings.TrimSpace(address)
	return btcLegacyRegex.MatchString(trimmed) || btcSegwitRegex.MatchString(trimmed)
}

func (d *BitcoinDriver) FetchWalletEvidence(ctx context.Context, address string) (*types.WalletEvidence, error) {
	trimmed := strings.TrimSpace(address)
	if !d.ValidateAddress(trimmed) {
		return nil, fmt.Errorf("invalid Bitcoin address format: %s", address)
	}

	evidence := &types.WalletEvidence{
		TargetType:        types.TargetTypeWallet,
		Network:           "bitcoin",
		Address:           trimmed,
		NormalizedAddress: trimmed,
		CollectedAt:       time.Now().UTC(),
		Wallet: types.WalletSummaryInfo{
			Address:          trimmed,
			Network:          "bitcoin",
			Balance:          "0.00 BTC",
			TransactionCount: 0,
		},
		Activity: types.WalletActivityEvidence{},
		Contracts: types.ContractInteractionEvidence{},
		Counterparties: types.CounterpartyEvidence{},
		FundFlow: types.FundFlowEvidence{},
	}

	return evidence, nil
}
