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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/kong/deck/sanitize"
	"github.com/kong/go-database-reconciler/pkg/dump"
	"github.com/kong/go-database-reconciler/pkg/file"
	"github.com/kong/go-database-reconciler/pkg/konnect"
	"github.com/kong/go-database-reconciler/pkg/state"
	"github.com/kong/go-database-reconciler/pkg/utils"
	"github.com/kong/go-kong/kong"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/objx"
)

// CollectKDD performs Kong configuration data collection.
func CollectKDD(ctx context.Context, cfg *Config) ([]string, error) {
	var summaryInfo SummaryInfo
	var finalResponse = make(map[string]interface{})
	var filesToZip []string

	kongAddr := cfg.KongAddr
	deckHeaders := cfg.RBACHeaders

	if !cfg.KonnectMode {
		// Get the Kong client
		client, err := utils.GetKongClient(utils.KongClientConfig{
			Address: kongAddr,
			TLSConfig: utils.TLSConfig{
				SkipVerify: true,
			},
			Debug:   false,
			Headers: deckHeaders,
		})

		if err != nil {
			log.WithError(err).Warn("Failed to get Kong client, skipping KDD collection")
			return filesToZip, nil
		}

		// response of GET request on the root of the Admin
		root, err := client.RootJSON(context.Background())
		if err != nil {
			log.WithError(err).Warn("Failed to get root JSON from Kong, skipping KDD collection")
			return filesToZip, nil
		}

		// create a map from the JSON response
		rootConfig, err := objx.FromJSON(string(root))
		if err != nil {
			log.WithError(err).Warn("Failed to parse root JSON, skipping KDD collection")
			return filesToZip, nil
		}

		// Get the status and list of workspaces
		status, err := getEndpoint(client, "/status")
		if err != nil {
			log.WithError(err).Warn("Failed to get status endpoint")
		}

		workspaces, err := getWorkspaces(client)
		if err != nil {
			log.WithError(err).Warn("Failed to get workspaces, skipping KDD collection")
			return filesToZip, nil
		}

		// Get the license report
		licenseReport, err := getEndpoint(client, "/license/report")
		if err != nil {
			log.WithError(err).Warn("Failed to get license report")
		}

		// Update the summaryInfo struct
		summaryInfo.TotalWorkspaceCount = len(workspaces.Data)
		summaryInfo.DeploymentTopology = rootConfig.Get("configuration.role").Str()
		summaryInfo.DatabaseType = rootConfig.Get("configuration.database").Str()
		summaryInfo.KongVersion = rootConfig.Get("version").Str()

		switch summaryInfo.DeploymentTopology {
		case "control_plane":
			summaryInfo.DeploymentTopology = "hybrid"
		case "traditional":
			if summaryInfo.DatabaseType == "off" {
				summaryInfo.DeploymentTopology = "DB-Less"
			}
		}

		// Add the root config, status, and license report to the final response map
		finalResponse["root_config"] = sanitizeRootConfig(rootConfig, cfg.SanitizeConfigs)
		finalResponse["status"] = status
		finalResponse["license_report"] = licenseReport

		//Incomplete data as yet, but saving what we've collected so far incase of error during workspace iteration
		finalResponse["summary_info"] = summaryInfo

		createWorkspaceConfigDumps := cfg.DumpWorkspaceConfigs

		// Process workspaces in parallel with controlled concurrency
		var wg sync.WaitGroup
		var mu sync.Mutex
		// Limit concurrent workspace processing to 5 to avoid overwhelming the API
		semaphore := make(chan struct{}, 5)

		for _, ws := range workspaces.Data {
			wg.Add(1)
			go func(workspace struct {
				Comment interface{} `json:"comment"`
				Config  struct {
					Meta                      interface{} `json:"meta"`
					Portal                    bool        `json:"portal"`
					PortalAccessRequestEmail  interface{} `json:"portal_access_request_email"`
					PortalApprovedEmail       interface{} `json:"portal_approved_email"`
					PortalAuth                interface{} `json:"portal_auth"`
					PortalAuthConf            interface{} `json:"portal_auth_conf"`
					PortalAutoApprove         interface{} `json:"portal_auto_approve"`
					PortalCorsOrigins         interface{} `json:"portal_cors_origins"`
					PortalDeveloperMetaFields string      `json:"portal_developer_meta_fields"`
					PortalEmailsFrom          interface{} `json:"portal_emails_from"`
					PortalEmailsReplyTo       interface{} `json:"portal_emails_reply_to"`
					PortalInviteEmail         interface{} `json:"portal_invite_email"`
					PortalIsLegacy            interface{} `json:"portal_is_legacy"`
					PortalResetEmail          interface{} `json:"portal_reset_email"`
					PortalResetSuccessEmail   interface{} `json:"portal_reset_success_email"`
					PortalSessionConf         interface{} `json:"portal_session_conf"`
					PortalTokenExp            interface{} `json:"portal_token_exp"`
				} `json:"config"`
				CreatedAt int    `json:"created_at"`
				ID        string `json:"id"`
				Meta      struct {
					Color     string      `json:"color"`
					Thumbnail interface{} `json:"thumbnail"`
				} `json:"meta"`
				Name string `json:"name"`
			}) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire semaphore
				defer func() { <-semaphore }() // Release semaphore

				log.WithField("workspace", workspace.Name).Info("Processing workspace")

				// Create a workspace-specific client to avoid race conditions
				wsClient, err := utils.GetKongClient(utils.KongClientConfig{
					Address: kongAddr,
					TLSConfig: utils.TLSConfig{
						SkipVerify: true,
					},
					Debug:   false,
					Headers: deckHeaders,
				})
				if err != nil {
					log.WithFields(log.Fields{
						"workspace": workspace.Name,
						"error":     err,
					}).Error("Failed to get Kong client for workspace")
					return
				}

				wsClient.SetWorkspace(workspace.Name)

				// Queries all the entities using client and returns all the entities in KongRawState.
				d, err := dump.Get(context.Background(), wsClient, dump.Config{
					RBACResourcesOnly: false,
					SkipConsumers:     false,
				})

				if err != nil {
					log.WithFields(log.Fields{
						"workspace": workspace.Name,
						"error":     err,
					}).Error("Error getting workspace data, continuing to next workspace")
					return
				}

				// Count regex routes
				regexRouteCount := 0
				for _, v := range d.Routes {
					for _, route := range v.Paths {
						if strings.HasPrefix(*route, "~") {
							regexRouteCount++
						}
					}
				}

				// Check if portal is enabled
				portalEnabled := 0
				if workspace.Config.Portal {
					portalEnabled = 1
				}

				// Update summary info with mutex protection
				mu.Lock()
				summaryInfo.TotalConsumerCount += len(d.Consumers)
				summaryInfo.TotalServiceCount += len(d.Services)
				summaryInfo.TotalRouteCount += len(d.Routes)
				summaryInfo.TotalPluginCount += len(d.Plugins)
				summaryInfo.TotalTargetCount += len(d.Targets)
				summaryInfo.TotalUpstreamCount += len(d.Upstreams)
				summaryInfo.TotalRegExRoutes += regexRouteCount
				summaryInfo.TotalEnabledDevPortalCount += portalEnabled
				mu.Unlock()

				if createWorkspaceConfigDumps {
					ks, err := state.Get(d)
					if err != nil {
						log.WithFields(log.Fields{
							"workspace": workspace.Name,
							"error":     err,
						}).Error("Error building Kong dump state")
						return
					}

					err = sanitizeKongState(ctx, wsClient, ks, file.WriteConfig{
						KongVersion: summaryInfo.KongVersion,
						Filename:    workspace.Name + "-kong-dump.yaml",
						FileFormat:  file.YAML,
					}, false, cfg.SanitizeConfigs)
					if err != nil {
						log.WithFields(log.Fields{
							"workspace": workspace.Name,
							"error":     err,
						}).Error("Error building Kong dump file")
					} else {
						log.WithField("workspace", workspace.Name).Info("Successfully dumped workspace")
						mu.Lock()
						filesToZip = append(filesToZip, workspace.Name+"-kong-dump.yaml")
						mu.Unlock()
					}
				}
			}(ws)
		}

		// Wait for all workspaces to be processed
		wg.Wait()

		// Add the full info now we know we have it all
		finalResponse["summary_info"] = summaryInfo

		jsonBytes, err := json.Marshal(finalResponse)
		if err != nil {
			log.WithError(err).Error("Error marshalling KDD data to JSON")
			return filesToZip, err
		}

		err = os.WriteFile("KDD.json", jsonBytes, 0644)
		if err != nil {
			log.WithError(err).Fatal("Error writing KDD.json")
			return filesToZip, err
		}

		filesToZip = append(filesToZip, "KDD.json")
		return filesToZip, nil
	}

	// Handle Konnect mode
	log.Info("Running in Konnect mode")
	httpClient := utils.HTTPClient()

	controlPlaneName := cfg.KonnectControlPlaneName

	// Setup the Konnect client
	log.WithField("deckHeaders", deckHeaders).Debug("Using deck headers")
	config := utils.KonnectConfig{
		ControlPlaneName: controlPlaneName,
		Token:            deckHeaders[0],
		Address:          kongAddr,
	}

	// Tack the token on as an auth header
	if config.Token != "" {
		config.Headers = append(
			config.Headers, "Authorization:Bearer "+config.Token,
		)
	}

	client, err := utils.GetKonnectClient(httpClient, config)
	if err != nil {
		log.WithError(err).Error("Failed to get Konnect client")
		return nil, err
	}

	// Before we do anything, we need to login
	authResponse, err := client.Auth.LoginV2(ctx, config.Email, config.Password, config.Token)
	if err != nil {
		log.WithError(err).Error("Failed to login to Konnect")
		return nil, err
	}

	log.WithFields(log.Fields{
		"name":     authResponse.Name,
		"orgID":    authResponse.OrganizationID,
		"org":      authResponse.Organization,
		"fullName": authResponse.FullName,
	}).Debug("Authenticated with Konnect")

	var listOpt *konnect.ListOpt
	controlPlanes, _, err := client.RuntimeGroups.List(ctx, listOpt)
	if err != nil {
		log.WithError(err).Error("Failed to list control planes")
		return nil, err
	}

	var cpID string
	for _, controlPlane := range controlPlanes {
		if *controlPlane.Name == controlPlaneName {
			cpID = *controlPlane.ID
			log.WithFields(log.Fields{
				"name": controlPlaneName,
				"id":   cpID,
			}).Info("Found control plane")
		}
	}

	if cpID == "" {
		log.WithField("controlPlaneName", controlPlaneName).Error("Control plane not found")
		return nil, fmt.Errorf("control plane %s not found", controlPlaneName)
	}

	konnectAddress := kongAddr + "/v2/control-planes/" + cpID + "/core-entities"
	kongClient, err := utils.GetKongClient(utils.KongClientConfig{
		Address:    konnectAddress,
		HTTPClient: httpClient,
		Debug:      config.Debug,
		Headers:    config.Headers,
		Retryable:  true,
		TLSConfig:  config.TLSConfig,
	})

	if err != nil {
		log.WithError(err).Error("Failed to get Kong client for Konnect")
		return nil, err
	}

	dumpConfig := cfg.DumpConfig
	dumpConfig.KonnectControlPlane = controlPlaneName
	rawState, err := dump.Get(ctx, kongClient, dumpConfig)
	if err != nil {
		log.WithError(err).Error("Failed reading configuration from Kong")
		return nil, fmt.Errorf("Failed reading configuration from Kong: %w", err)
	}

	summaryInfo.TotalConsumerCount = len(rawState.Consumers)
	summaryInfo.TotalServiceCount = len(rawState.Services)
	summaryInfo.TotalRouteCount = len(rawState.Routes)
	summaryInfo.TotalPluginCount = len(rawState.Plugins)
	summaryInfo.TotalTargetCount = len(rawState.Targets)
	summaryInfo.TotalUpstreamCount = len(rawState.Upstreams)

	if cfg.DumpWorkspaceConfigs {
		ks, err := state.Get(rawState)
		if err != nil {
			log.WithError(err).Error("Failed building state")
			return nil, fmt.Errorf("building state: %w", err)
		}

		filename := "konnect-" + controlPlaneName + ".yaml"
		err = sanitizeKongState(ctx, kongClient, ks, file.WriteConfig{
			SelectTags:       dumpConfig.SelectorTags,
			Filename:         filename,
			FileFormat:       file.YAML,
			WithID:           true,
			ControlPlaneName: controlPlaneName,
			KongVersion:      "3.5.0.0", // placeholder
		}, true, cfg.SanitizeConfigs)

		if err != nil {
			log.WithFields(log.Fields{
				"controlPlane": controlPlaneName,
				"error":        err,
			}).Error("Failed building Kong dump file")
		} else {
			log.WithField("controlPlane", controlPlaneName).Info("Successfully dumped Control Plane")
			filesToZip = append(filesToZip, filename)
		}
	}

	finalResponse["summary_info"] = summaryInfo

	jsonBytes, err := json.Marshal(finalResponse)
	if err != nil {
		log.WithError(err).Error("Error marshalling JSON")
		return nil, err
	}

	err = os.WriteFile("KDD.json", jsonBytes, 0644)
	if err != nil {
		log.WithError(err).Fatal("Error writing KDD.json")
		return filesToZip, err
	}

	filesToZip = append(filesToZip, "KDD.json")
	return filesToZip, nil
}

// formatJSON formats JSON data with indentation.
func formatJSON(data []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", "    ")
	if err == nil {
		return out.Bytes(), err
	}
	return data, nil
}

// sanitizeKongState sanitizes a Kong state and writes it to a file.
func sanitizeKongState(ctx context.Context, client *kong.Client, ks *state.KongState, writeConfig file.WriteConfig, isKonnect bool, sanitizeConfigs bool) error {
	if !sanitizeConfigs {
		// If sanitization is disabled, use the regular write method
		return file.KongStateToFile(ks, writeConfig)
	}

	// Convert Kong state to file content
	writeConfig.WithID = true // always write IDs for sanitization
	fileContent, err := file.KongStateToContent(ks, writeConfig)
	if err != nil {
		return fmt.Errorf("converting Kong state to content: %w", err)
	}

	// Create sanitizer with empty salt (will auto-generate random salt)
	sanitizer := sanitize.NewSanitizer(&sanitize.SanitizerOptions{
		Ctx:       ctx,
		Client:    client,
		Content:   fileContent,
		IsKonnect: isKonnect,
		Salt:      "", // Empty salt triggers automatic random salt generation
	})

	// Sanitize content
	sanitizedContent, err := sanitizer.Sanitize()
	if err != nil {
		return fmt.Errorf("sanitizing content: %w", err)
	}

	// Write sanitized content to file
	return file.WriteContentToFile(sanitizedContent, writeConfig.Filename, writeConfig.FileFormat)
}

// sanitizeRootConfig sanitizes sensitive fields in the Kong root configuration.
func sanitizeRootConfig(config objx.Map, sanitizeConfigs bool) objx.Map {
	if !sanitizeConfigs {
		return config
	}

	// Create a copy to avoid mutating the original
	sanitized := objx.New(config)

	// List of sensitive configuration keys that should be redacted
	sensitiveKeys := []string{
		"pg_password",
		"cassandra_password",
		"admin_gui_session_conf",
		"portal_session_conf",
		"vitals_tsdb_address",
		"cluster_cert_key",
		"ssl_cert_key",
		"admin_ssl_cert_key",
		"client_ssl_cert_key",
	}

	// Redact sensitive configuration values
	if confValue := sanitized.Get("configuration"); confValue.IsObjxMap() {
		confMap := confValue.ObjxMap()
		for _, key := range sensitiveKeys {
			if confMap.Has(key) {
				confMap.Set(key, "<REDACTED>")
			}
		}
	}

	return sanitized
}

// getEndpoint retrieves data from a Kong Admin API endpoint.
func getEndpoint(client *kong.Client, endpoint string) (objx.Map, error) {
	req, err := client.NewRequest("GET", endpoint, nil, nil)
	if err != nil {
		return nil, err
	}

	oReturn, err := getObjx(req, client)
	if err != nil {
		return nil, err
	}

	return oReturn, nil
}

// getObjx performs an HTTP request and returns the response as an objx.Map.
func getObjx(req *http.Request, client *kong.Client) (objx.Map, error) {
	resp, err := client.DoRAW(context.Background(), req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	strBody := string(body)
	oReturn, err := objx.FromJSON(strBody)
	if err != nil {
		return nil, err
	}

	return oReturn, nil
}

// getWorkspaces retrieves the list of workspaces from Kong.
func getWorkspaces(client *kong.Client) (*Workspaces, error) {
	req, err := client.NewRequest("GET", "/workspaces", nil, nil)
	if err != nil {
		return nil, err
	}

	var w Workspaces
	_, err = client.Do(context.Background(), req, &w)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// parseHeaders parses a slice of header strings into an http.Header.
func parseHeaders(headers []string) (http.Header, error) {
	res := http.Header{}
	const splitLen = 2

	for _, keyValue := range headers {
		split := strings.SplitN(keyValue, ":", 2)
		if len(split) >= splitLen {
			res.Add(split[0], split[1])
		} else {
			return nil, fmt.Errorf("splitting header key-value '%s'", keyValue)
		}
	}

	return res, nil
}
