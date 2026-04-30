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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
)

// Runtime constants
const (
	RuntimeDocker     = "docker"
	RuntimeKubernetes = "kubernetes"
	RuntimeVM         = "vm"
	LineLimitDefault  = int64(1000)
)

// VM log file constants
const (
	VMMemoryLogFile  = "vm-memory-summary.json"
	VMCPULogFile     = "vm-cpu-summary.json"
	VMDiskLogFile    = "vm-disk-summary.json"
	VMProcessLogFile = "vm-process-summary.json"
	VMNetworkLogFile = "vm-network-summary.json"
	VMHostsFile      = "vm-hosts"
	VMResolvFile     = "vm-resolv.conf"
)

// Result holds the output of a collection run.
type Result struct {
	// ArchivePath is the path to the created tar.gz archive.
	ArchivePath string

	// Runtime is the runtime that was detected or specified.
	Runtime string

	// CollectedFiles is the list of files that were collected (before archiving).
	CollectedFiles []string

	// Warnings contains any non-fatal errors encountered during collection.
	Warnings []error
}

// Summary contains basic Kong deployment information.
type Summary struct {
	Version  string
	Portal   string
	Vitals   string
	DBMode   string
	Platform string
}

// MemoryInfo contains VM memory statistics.
type MemoryInfo struct {
	PhysicalTotal     float64
	PhysicalAvailable float64
	SwapTotal         float64
	SwapFree          float64
}

// CPUInfo contains VM CPU statistics.
type CPUInfo struct {
	CPU   int
	Cores int32
}

// DiskInfo contains VM disk statistics.
type DiskInfo struct {
	Total       uint64
	Free        uint64
	Used        uint64
	UsedPercent float64
}

// ProcessInfo contains information about a running process.
type ProcessInfo struct {
	Name       string
	PID        int32
	CPUPercent string
	MemPercent uint64
	CmdLine    string
}

// NetworkInfo contains network connection information.
type NetworkInfo struct {
	Fd     uint32  `json:"fd"`
	Family uint32  `json:"family"`
	Type   uint32  `json:"type"`
	Laddr  string  `json:"localaddr"`
	Raddr  string  `json:"remoteaddr"`
	Status string  `json:"status"`
	Uids   []int32 `json:"uids"`
	Pid    int32   `json:"pid"`
}

// PortForwardAPodRequest contains the configuration for port forwarding to a pod.
type PortForwardAPodRequest struct {
	// RestConfig is the kubernetes config
	RestConfig *rest.Config
	// Pod is the selected pod for this port forwarding
	Pod corev1.Pod
	// LocalPort is the local port that will be selected to expose the PodPort
	LocalPort int
	// PodPort is the target port for the pod
	PodPort int
	// Streams configures where to write or read input from
	Streams genericclioptions.IOStreams
	// StopCh is the channel used to manage the port forward lifecycle
	StopCh <-chan struct{}
	// ReadyCh communicates when the tunnel is ready to receive traffic
	ReadyCh chan struct{}
}

// NamedCommand represents a command with an associated name for output files.
type NamedCommand struct {
	Cmd  []string
	Name string
}

// Status contains Kong status endpoint response.
type Status struct {
	Database struct {
		Reachable bool `json:"reachable"`
	} `json:"database"`
	Memory struct {
		LuaSharedDicts struct {
			Kong struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong"`
			KongClusterEvents struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_cluster_events"`
			KongCoreDbCache struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_core_db_cache"`
			KongCoreDbCacheMiss struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_core_db_cache_miss"`
			KongCounters struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_counters"`
			KongDbCache struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_db_cache"`
			KongDbCacheMiss struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_db_cache_miss"`
			KongHealthchecks struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_healthchecks"`
			KongKeyring struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_keyring"`
			KongLocks struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_locks"`
			KongProcessEvents struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_process_events"`
			KongRateLimitingCounters struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_rate_limiting_counters"`
			KongReportsConsumers struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_reports_consumers"`
			KongReportsRoutes struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_reports_routes"`
			KongReportsServices struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_reports_services"`
			KongReportsWorkspaces struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_reports_workspaces"`
			KongVitals struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_vitals"`
			KongVitalsCounters struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_vitals_counters"`
			KongVitalsLists struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"kong_vitals_lists"`
			PrometheusMetrics struct {
				AllocatedSlabs string `json:"allocated_slabs"`
				Capacity       string `json:"capacity"`
			} `json:"prometheus_metrics"`
		} `json:"lua_shared_dicts"`
		WorkersLuaVms []struct {
			HTTPAllocatedGc string `json:"http_allocated_gc"`
			Pid             int    `json:"pid"`
		} `json:"workers_lua_vms"`
	} `json:"memory"`
	Server struct {
		ConnectionsAccepted int `json:"connections_accepted"`
		ConnectionsActive   int `json:"connections_active"`
		ConnectionsHandled  int `json:"connections_handled"`
		ConnectionsReading  int `json:"connections_reading"`
		ConnectionsWaiting  int `json:"connections_waiting"`
		ConnectionsWriting  int `json:"connections_writing"`
		TotalRequests       int `json:"total_requests"`
	} `json:"server"`
	ConfigurationHash string `json:"configuration_hash,omitempty" yaml:"configuration_hash,omitempty"`
}

// Workspaces contains the list of Kong workspaces.
type Workspaces struct {
	Data []struct {
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
	} `json:"data"`
	Next interface{} `json:"next"`
}

// SummaryInfo contains aggregated information about a Kong deployment.
type SummaryInfo struct {
	DatabaseType               string `json:"database_type"`
	DeploymentTopology         string `json:"deployment_topology"`
	KongVersion                string `json:"kong_version"`
	TotalConsumerCount         int    `json:"total_consumer_count"`
	TotalDataplaneCount        int    `json:"total_dataplane_count"`
	TotalEnabledDevPortalCount int    `json:"total_enabled_dev_portal_count"`
	TotalPluginCount           int    `json:"total_plugin_count"`
	TotalRouteCount            int    `json:"total_route_count"`
	TotalServiceCount          int    `json:"total_service_count"`
	TotalTargetCount           int    `json:"total_target_count"`
	TotalUpstreamCount         int    `json:"total_upstream_count"`
	TotalWorkspaceCount        int    `json:"total_workspace_count"`
	TotalRegExRoutes           int    `json:"total_regex_route_count"`
}

// CustomMessage is a simple message container.
type CustomMessage struct {
	Message string `json:"message"`
}
