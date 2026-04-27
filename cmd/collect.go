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
	"os"
	"strconv"
	"strings"

	"github.com/kong/kong-debug-tool/pkg/collector"
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
		}

		// Apply environment variable overrides (backward compatibility).
		// These were previously checked inside the library but are now
		// handled at the CLI layer so the library only uses Config values.
		applyEnvVarOverrides(cfg)

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
	collectCmd.PersistentFlags().StringVar(&logsSinceDocker, "docker-since", "", "Return logs newer than a relative duration like 5s, 2m, or 3h. Used with docker runtime only. Will override --line-limit if set.")
	collectCmd.PersistentFlags().Int64Var(&logsSinceSeconds, "k8s-since-seconds", 0, "Return logs newer than the seconds past. Used with K8s runtime only. Will override --line-limit if set.")
	collectCmd.PersistentFlags().Int64Var(&lineLimit, "line-limit", collector.LineLimitDefault, "Return logs with this amount of lines retrieved. Defaults to 1000 lines. Used with all runtimes as a default. --k8s-since-seconds and --docker-since will both override this setting.")
	collectCmd.PersistentFlags().StringVarP(&prefixDir, "prefix-dir", "k", "/usr/local/kong", "The path to your prefix directory for determining VM log locations. Default: /usr/local/kong")
	collectCmd.PersistentFlags().BoolVarP(&disableKDDCollection, "disable-kdd", "q", false, "Disable KDD config collection. Default: false.")
	collectCmd.PersistentFlags().StringSliceVarP(&strToRedact, "redact-logs", "R", nil, "CSV list of terms to redact during log extraction.")
	collectCmd.PersistentFlags().BoolVarP(&sanitizeConfigs, "sanitize", "s", true, "Sanitize sensitive data in config dumps. Default: true.")
}

// applyEnvVarOverrides applies environment variable overrides to the collector config.
// This preserves backward compatibility for standalone kdt usage. When used as a library
// (e.g., from kongctl), the calling code controls all Config values directly.
func applyEnvVarOverrides(cfg *collector.Config) {
	if v := os.Getenv("KONG_RUNTIME"); v != "" && cfg.Runtime == "" {
		cfg.Runtime = v
	}
	if v := os.Getenv("KONG_ADDR"); v != "" {
		cfg.KongAddr = v
	}
	if v := os.Getenv("RBAC_HEADER"); v != "" {
		cfg.RBACHeaders = strings.Split(v, ",")
	}
	if os.Getenv("KONG_KONNECT_MODE") != "" {
		// Use KONG_KDD_KONNECT to avoid collision with native Kong variable KONG_KONNECT_MODE
		// https://docs.konghq.com/gateway/latest/reference/configuration/#konnect_mode
		if v, err := strconv.ParseBool(os.Getenv("KONG_KDD_KONNECT")); err == nil {
			cfg.KonnectMode = v
		}
	}
	if v := os.Getenv("DISABLE_KDD"); v != "" {
		cfg.DisableKDD = (v == "true")
	}
	if v := os.Getenv("DUMP_WORKSPACE_CONFIGS"); v != "" {
		cfg.DumpWorkspaceConfigs = (v == "true")
	}
	if v := os.Getenv("DOCKER_LOGS_SINCE"); v != "" {
		cfg.DockerLogsSince = v
	}
	if v := os.Getenv("TARGET_PODS"); v != "" {
		cfg.TargetPods = strings.Split(v, ",")
	}
	if v := os.Getenv("K8S_LOGS_SINCE_SECONDS"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.K8sLogsSinceSeconds = parsed
		}
	}
}
