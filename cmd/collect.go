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
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kong/kong-deployment-toolkit/pkg/collector"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// CLI flags
	rType                      string
	konnectMode                bool
	controlPlaneName           string
	kongImages                 []string
	deckHeaders                []string
	targetPods                 []string
	prefixDir                  string
	logsSinceDocker            string
	lineLimit                  int64
	logsSinceSeconds           int64
	kongAddr                   string
	createWorkspaceConfigDumps bool
	disableKDDCollection       bool
	strToRedact                []string
	sanitizeConfigs            bool
	namespace                  string
	tlsSkipVerify              bool
	caCertPath                 string
)

var collectCmd = &cobra.Command{
	Use:    "collect",
	Short:  "Collect Kong and Environment information",
	Long:   `Collect Kong and Environment information.`,
	PreRun: toggleDebug,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Build the collector configuration from CLI flags
		cfg := &collector.Config{
			Runtime:                 rType,
			KongAddr:                kongAddr,
			RBACHeaders:             deckHeaders,
			TargetImages:            kongImages,
			TargetPods:              targetPods,
			Namespace:               namespace,
			DisableKDD:              disableKDDCollection,
			DumpWorkspaceConfigs:    createWorkspaceConfigDumps,
			SanitizeConfigs:         sanitizeConfigs,
			KonnectMode:             konnectMode,
			KonnectControlPlaneName: controlPlaneName,
			RedactTerms:             strToRedact,
			LineLimit:               lineLimit,
			DockerLogsSince:         logsSinceDocker,
			K8sLogsSinceSeconds:     logsSinceSeconds,
			PrefixDir:               prefixDir,
			Debug:                   debug,
			TLSSkipVerify:           tlsSkipVerify,
			CACertPath:              caCertPath,
		}

		// Apply environment variable overrides (backward compatibility).
		// These were previously checked inside the library but are now
		// handled at the CLI layer so the library only uses Config values.
		applyEnvVarOverrides(cmd, cfg)

		if err := validateRuntime(cfg.Runtime); err != nil {
			return err
		}

		// Run the collector
		ctx := context.Background()
		result, err := collector.Collect(ctx, cfg)
		if err != nil {
			return err
		}

		// Log any warnings
		for _, warning := range result.Warnings {
			log.WithError(warning).Warn("Collection warning")
		}

		if result.ArchivePath != "" {
			log.WithField("archive", result.ArchivePath).Info("Collection completed successfully")
		}

		return nil
	},
}

var (
	defaultKongImageList = []string{"kong-gateway", "kubernetes-ingress-controller"}
)

func init() {
	rootCmd.AddCommand(collectCmd)
	collectCmd.PersistentFlags().StringVarP(&controlPlaneName, "konnect-control-plane-name", "c", "", "Konnect Control Plane name.")
	collectCmd.PersistentFlags().StringVarP(&rType, "runtime", "r", "", "Runtime to extract logs from (kubernetes or docker). Runtime is auto detected if omitted.")
	collectCmd.PersistentFlags().BoolVarP(&konnectMode, "konnect-mode", "x", false, "Enables Konnect mode. This will use the Konnect API to collect data.")
	collectCmd.PersistentFlags().StringSliceVarP(&kongImages, "target-images", "i", defaultKongImageList, `Override default gateway images to scrape logs from. Default: "kong-gateway","kubernetes-ingress-controller"`)
	collectCmd.PersistentFlags().StringSliceVarP(&deckHeaders, "rbac-header", "H", nil, "RBAC header required to contact the admin-api.")
	collectCmd.PersistentFlags().StringVarP(&kongAddr, "kong-addr", "a", "http://localhost:8001", "The address to reach the admin-api of the Kong instance in question.")
	collectCmd.PersistentFlags().BoolVarP(&createWorkspaceConfigDumps, "dump-workspace-configs", "d", false, "Deck dump workspace configs to yaml files. Default: false. NOTE: Will not work if --disable-kdd=true")
	collectCmd.PersistentFlags().StringSliceVarP(&targetPods, "target-pods", "p", nil, "CSV list of pod names to target when extracting logs. Default is to scan all running pods for Kong images.")
	collectCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace to collect from. Required when --runtime=kubernetes.")
	collectCmd.PersistentFlags().StringVar(&logsSinceDocker, "docker-since", "", "Return logs newer than a relative duration like 5s, 2m, or 3h. Used with docker runtime only. Will override --line-limit if set.")
	collectCmd.PersistentFlags().Int64Var(&logsSinceSeconds, "k8s-since-seconds", 0, "Return logs newer than the seconds past. Used with K8s runtime only. Will override --line-limit if set.")
	collectCmd.PersistentFlags().Int64Var(&lineLimit, "line-limit", collector.LineLimitDefault, "Return logs with this amount of lines retrieved. Defaults to 1000 lines. Used with all runtimes as a default. --k8s-since-seconds and --docker-since will both override this setting.")
	collectCmd.PersistentFlags().StringVarP(&prefixDir, "prefix-dir", "k", "/usr/local/kong", "The path to your prefix directory for determining VM log locations. Default: /usr/local/kong")
	collectCmd.PersistentFlags().BoolVarP(&disableKDDCollection, "disable-kdd", "q", false, "Disable KDD config collection. Default: false.")
	collectCmd.PersistentFlags().StringSliceVarP(&strToRedact, "redact-logs", "R", nil, "CSV list of terms to redact during log extraction.")
	collectCmd.PersistentFlags().BoolVarP(&sanitizeConfigs, "sanitize", "s", true, "Sanitize sensitive data in config dumps. Default: true.")
	collectCmd.PersistentFlags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification when connecting to the Kong Admin API. WARNING: insecure, allows on-path interception of credentials. Default: false.")
	collectCmd.PersistentFlags().StringVar(&caCertPath, "ca-cert", "", "Path to a PEM-encoded CA certificate bundle to verify the Kong Admin API's TLS certificate.")
}

// validateRuntime rejects a --runtime/KONG_RUNTIME value that isn't one of the
// supported runtimes (or empty, for auto-detect), so a typo produces a clear
// error immediately instead of surfacing as "runtime %q not supported" deeper
// inside collector.Collect.
func validateRuntime(runtime string) error {
	switch runtime {
	case "", collector.RuntimeDocker, collector.RuntimeKubernetes, collector.RuntimeVM:
		return nil
	default:
		return fmt.Errorf("invalid --runtime %q: must be one of %q, %q, %q, or omitted to auto-detect",
			runtime, collector.RuntimeDocker, collector.RuntimeKubernetes, collector.RuntimeVM)
	}
}

// applyEnvVarOverrides applies environment variable overrides to the collector config.
// This preserves backward compatibility for standalone kdt usage. When used as a library
// (e.g., from kongctl), the calling code controls all Config values directly.
//
// An override is only applied when the corresponding flag was not explicitly set on the
// command line, so an explicit flag always wins over an environment variable. Boolean and
// integer overrides are parsed with strconv; an unparseable value is logged and ignored
// rather than silently coercing to false/zero.
func applyEnvVarOverrides(cmd *cobra.Command, cfg *collector.Config) {
	if v := os.Getenv("KONG_RUNTIME"); v != "" && !cmd.Flags().Changed("runtime") {
		cfg.Runtime = v
	}
	if v := os.Getenv("KONG_ADDR"); v != "" && !cmd.Flags().Changed("kong-addr") {
		cfg.KongAddr = v
	}
	if v := os.Getenv("RBAC_HEADER"); v != "" && !cmd.Flags().Changed("rbac-header") {
		// Comma-separated; a header value containing a literal comma cannot be
		// represented this way (use --rbac-header, which can be repeated, instead).
		cfg.RBACHeaders = strings.Split(v, ",")
	}
	if os.Getenv("KONG_KONNECT_MODE") != "" && !cmd.Flags().Changed("konnect-mode") {
		// Use KONG_KDD_KONNECT to avoid collision with native Kong variable KONG_KONNECT_MODE
		// https://docs.konghq.com/gateway/latest/reference/configuration/#konnect_mode
		if v, err := strconv.ParseBool(os.Getenv("KONG_KDD_KONNECT")); err == nil {
			cfg.KonnectMode = v
		} else {
			log.WithError(err).Warn("KONG_KDD_KONNECT is not a valid boolean, ignoring KONG_KONNECT_MODE override")
		}
	}
	if v := os.Getenv("DISABLE_KDD"); v != "" && !cmd.Flags().Changed("disable-kdd") {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.DisableKDD = parsed
		} else {
			log.WithError(err).Warn("DISABLE_KDD is not a valid boolean, ignoring")
		}
	}
	if v := os.Getenv("DUMP_WORKSPACE_CONFIGS"); v != "" && !cmd.Flags().Changed("dump-workspace-configs") {
		if parsed, err := strconv.ParseBool(v); err == nil {
			cfg.DumpWorkspaceConfigs = parsed
		} else {
			log.WithError(err).Warn("DUMP_WORKSPACE_CONFIGS is not a valid boolean, ignoring")
		}
	}
	if v := os.Getenv("DOCKER_LOGS_SINCE"); v != "" && !cmd.Flags().Changed("docker-since") {
		cfg.DockerLogsSince = v
	}
	if v := os.Getenv("TARGET_PODS"); v != "" && !cmd.Flags().Changed("target-pods") {
		cfg.TargetPods = strings.Split(v, ",")
	}
	if v := os.Getenv("K8S_NAMESPACE"); v != "" && !cmd.Flags().Changed("namespace") {
		cfg.Namespace = v
	}
	if v := os.Getenv("K8S_LOGS_SINCE_SECONDS"); v != "" && !cmd.Flags().Changed("k8s-since-seconds") {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.K8sLogsSinceSeconds = parsed
		} else {
			log.WithError(err).Warn("K8S_LOGS_SINCE_SECONDS is not a valid integer, ignoring")
		}
	}
}
