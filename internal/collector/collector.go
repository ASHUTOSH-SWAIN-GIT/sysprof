// Package collector produces cumulative syscall latency entries.
package collector

import "github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/model"

// Collector is implemented by the real eBPF collector (Linux only) and the
// fake one, so everything above it can be developed without a kernel.
type Collector interface {
	// Read returns the cumulative state of every (process, syscall) pair.
	Read() ([]model.Entry, error)
	Close() error
}
