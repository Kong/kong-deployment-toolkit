/*
Copyright © 2022 John Harris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package collector

import (
	"io"

	"github.com/kong/go-database-reconciler/pkg/dump"
)

// Config holds all configuration for the data collection process.
// This struct replaces the global variables that were previously in cmd/collect.go.
type Config struct {
	// Runtime specifies the deployment runtime to collect from.
	// Valid values: "docker", "kubernetes", "vm", or "" for auto-detect.
	Runtime string

	// KongAddr is the address of the Kong Admin API.
	// Default: "http://localhost:8001"
	KongAddr string

	// RBACHeaders are headers required to authenticate with the Kong Admin API.
	// Format: "Header-Name:header-value"
	RBACHeaders []string

	// TargetImages is a list of container image name substrings to identify Kong containers.
	// Default: ["kong-gateway", "kubernetes-ingress-controller"]
	TargetImages []string

	// TargetPods is an optional list of specific pod names to collect from (Kubernetes only).
	// If empty, all pods matching TargetImages will be collected.
	TargetPods []string

	// Namespace scopes Kubernetes pod collection to a single namespace.
	// Required when Runtime is kubernetes.
	Namespace string

	// DisableKDD disables Kong configuration (KDD) collection.
	// Default: false
	DisableKDD bool

	// DumpWorkspaceConfigs enables dumping workspace configurations to YAML files.
	// Only works if DisableKDD is false.
	// Default: false
	DumpWorkspaceConfigs bool

	// SanitizeConfigs enables sanitization of sensitive data in config dumps.
	// Default: true
	SanitizeConfigs bool

	// KonnectMode enables Konnect API mode for collection.
	// Default: false
	KonnectMode bool

	// KonnectControlPlaneName is the name of the Konnect control plane to collect from.
	// Required when KonnectMode is true.
	KonnectControlPlaneName string

	// RedactTerms is a list of terms to redact from collected logs.
	// Case-insensitive matching is used.
	RedactTerms []string

	// LineLimit is the maximum number of log lines to collect per source.
	// Default: 1000
	LineLimit int64

	// DockerLogsSince limits Docker log collection to logs newer than this duration.
	// Format: relative duration like "5s", "2m", or "3h".
	// If set, overrides LineLimit for Docker collection.
	DockerLogsSince string

	// K8sLogsSinceSeconds limits Kubernetes log collection to logs newer than this many seconds.
	// If set, overrides LineLimit for Kubernetes collection.
	K8sLogsSinceSeconds int64

	// PrefixDir is the Kong prefix directory for VM deployments.
	// Default: "/usr/local/kong"
	PrefixDir string

	// OutputDir is the directory where output files will be written.
	// If empty, the current working directory is used.
	OutputDir string

	// DumpConfig holds additional configuration for the deck dump process.
	DumpConfig dump.Config

	// Logger is an optional writer for log output.
	// If nil, logs go to stdout via logrus.
	Logger io.Writer

	// Debug enables verbose debug logging.
	Debug bool
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		KongAddr:     "http://localhost:8001",
		TargetImages: []string{"kong-gateway", "kubernetes-ingress-controller"},
		LineLimit:    1000,
		PrefixDir:    "/usr/local/kong",
	}
}

// WithDefaults returns a copy of the config with default values applied
// for any fields that are not set.
func (c *Config) WithDefaults() *Config {
	if c == nil {
		return DefaultConfig()
	}

	result := *c // Copy

	if result.KongAddr == "" {
		result.KongAddr = "http://localhost:8001"
	}
	if len(result.TargetImages) == 0 {
		result.TargetImages = []string{"kong-gateway", "kubernetes-ingress-controller"}
	}
	if result.LineLimit == 0 {
		result.LineLimit = 1000
	}
	if result.PrefixDir == "" {
		result.PrefixDir = "/usr/local/kong"
	}

	return &result
}
