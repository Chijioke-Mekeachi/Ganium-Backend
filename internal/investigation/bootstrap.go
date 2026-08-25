package investigation

import (
	"sync"

	"ganium/internal/config"
)

var (
	defaultManager *Manager
	defaultOnce    sync.Once
)

// Default returns the process-wide investigation manager.
func Default() *Manager {
	defaultOnce.Do(func() {
		defaultManager = NewManagerFromConfig(config.LoadFromEnv())
	})
	return defaultManager
}

// SetDefault replaces the process-wide manager. It is primarily useful in tests.
func SetDefault(m *Manager) {
	defaultManager = m
}
