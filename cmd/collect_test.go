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

package cmd

import (
	"testing"

	"github.com/kong/kong-deployment-toolkit/pkg/collector"
	"github.com/spf13/cobra"
)

// newTestCollectCmd builds a *cobra.Command with the same flags applyEnvVarOverrides
// inspects via Changed(), so tests can simulate a flag being explicitly set on the CLI.
func newTestCollectCmd() *cobra.Command {
	c := &cobra.Command{Use: "collect"}
	c.Flags().String("runtime", "", "")
	c.Flags().String("kong-addr", "http://localhost:8001", "")
	c.Flags().StringSlice("rbac-header", nil, "")
	c.Flags().Bool("konnect-mode", false, "")
	c.Flags().Bool("disable-kdd", false, "")
	c.Flags().Bool("dump-workspace-configs", false, "")
	c.Flags().String("docker-since", "", "")
	c.Flags().StringSlice("target-pods", nil, "")
	c.Flags().String("namespace", "", "")
	c.Flags().Int64("k8s-since-seconds", 0, "")
	return c
}

func TestApplyEnvVarOverrides_BooleanParsing(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		envVal  string
		check   func(cfg *collector.Config) bool
		wantSet bool
	}{
		{"DISABLE_KDD true", "DISABLE_KDD", "true", func(c *collector.Config) bool { return c.DisableKDD }, true},
		{"DISABLE_KDD 1", "DISABLE_KDD", "1", func(c *collector.Config) bool { return c.DisableKDD }, true},
		{"DISABLE_KDD TRUE (case-insensitive)", "DISABLE_KDD", "TRUE", func(c *collector.Config) bool { return c.DisableKDD }, true},
		{"DISABLE_KDD unparseable value is ignored, not coerced to false", "DISABLE_KDD", "yes", func(c *collector.Config) bool { return c.DisableKDD }, false},
		{"DUMP_WORKSPACE_CONFIGS true", "DUMP_WORKSPACE_CONFIGS", "true", func(c *collector.Config) bool { return c.DumpWorkspaceConfigs }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envVar, tt.envVal)

			cmd := newTestCollectCmd()
			cfg := &collector.Config{}
			applyEnvVarOverrides(cmd, cfg)

			if got := tt.check(cfg); got != tt.wantSet {
				t.Errorf("%s=%q: got %v, want %v", tt.envVar, tt.envVal, got, tt.wantSet)
			}
		})
	}
}

func TestApplyEnvVarOverrides_ExplicitFlagWinsOverEnv(t *testing.T) {
	t.Setenv("DISABLE_KDD", "true")

	cmd := newTestCollectCmd()
	if err := cmd.Flags().Set("disable-kdd", "false"); err != nil {
		t.Fatalf("setting flag: %v", err)
	}

	cfg := &collector.Config{DisableKDD: false}
	applyEnvVarOverrides(cmd, cfg)

	if cfg.DisableKDD {
		t.Errorf("DISABLE_KDD env var overrode an explicitly-set --disable-kdd flag")
	}
}

func TestApplyEnvVarOverrides_NamespaceAppliesOnlyWhenUnset(t *testing.T) {
	t.Setenv("K8S_NAMESPACE", "from-env")

	cmd := newTestCollectCmd()
	cfg := &collector.Config{}
	applyEnvVarOverrides(cmd, cfg)

	if cfg.Namespace != "from-env" {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, "from-env")
	}

	// Now with the flag explicitly set, the env var must not override it.
	cmd2 := newTestCollectCmd()
	if err := cmd2.Flags().Set("namespace", "from-flag"); err != nil {
		t.Fatalf("setting flag: %v", err)
	}
	cfg2 := &collector.Config{Namespace: "from-flag"}
	applyEnvVarOverrides(cmd2, cfg2)

	if cfg2.Namespace != "from-flag" {
		t.Errorf("Namespace = %q, want %q (env var should not override explicit flag)", cfg2.Namespace, "from-flag")
	}
}
