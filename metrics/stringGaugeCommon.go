package metrics

import (
	"github.com/gatechain/go-deadlock"
)

// StringGauge represents a map of key value pairs available to be written with the AddMetric
type StringGauge struct {
	deadlock.Mutex
	values map[string]string
}
