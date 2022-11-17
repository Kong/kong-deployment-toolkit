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
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"

	//"crypto/tls"
	//"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/kong/deck/dump"
	"github.com/kong/deck/file"
	"github.com/kong/deck/state"
	"github.com/kong/deck/utils"
	"github.com/kong/go-kong/kong"
	"github.com/spf13/cobra"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	//"github.com/ssgelm/cookiejarparser"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"

	// kongv1 "github.com/kong/kubernetes-ingress-controller/v2/pkg/apis/configuration/v1"
	// kongv1beta1 "github.com/kong/kubernetes-ingress-controller/v2/pkg/apis/configuration/v1beta1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// netv1 "k8s.io/api/networking/v1"
	"github.com/stretchr/objx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	Docker           = "docker"
	Kubernetes       = "kubernetes"
	VM               = "vm"
	LineLimitDefault = int64(1000)
)

var (
	rType                      string
	kongImages                 []string
	deckHeaders                []string
	targetPods                 []string
	kongConf                   string
	prefixDir                  string
	logsSinceDocker            string
	lineLimit                  int64
	logsSinceSeconds           int64
	clientTimeout              time.Duration
	rootConfig                 objx.Map
	kongAddr                   string
	createWorkspaceConfigDumps bool
	disableKDDCollection       bool
	strToRedact                []string
)

type Summary struct {
	Version  string
	Portal   string
	Vitals   string
	DBMode   string
	Platform string
}

type PortForwardAPodRequest struct {
	// RestConfig is the kubernetes config
	RestConfig *rest.Config
	// Pod is the selected pod for this port forwarding
	Pod corev1.Pod
	// LocalPort is the local port that will be selected to expose the PodPort
	LocalPort int
	// PodPort is the target port for the pod
	PodPort int
	// Steams configures where to write or read input from
	Streams genericclioptions.IOStreams
	// StopCh is the channel used to manage the port forward lifecycle
	StopCh <-chan struct{}
	// ReadyCh communicates when the tunnel is ready to receive traffic
	ReadyCh chan struct{}
}

var collectCmd = &cobra.Command{
	Use:    "collect",
	Short:  "Collect Kong and Environment information",
	Long:   `Collect Kong and Environment information.`,
	PreRun: toggleDebug,
	RunE: func(cmd *cobra.Command, args []string) error {

		var filesToZip []string

		if rType == "" {
			rType = os.Getenv("KONG_RUNTIME")
		}

		if rType == "" {
			log.Info("No runtime detected, attempting to guess runtime...")
			runtime, err := guessRuntime()
			if err != nil {
				return err
			}
			rType = runtime
		}

		switch rType {
		case "docker":

			if dockerFilesToZip, err := runDocker(); err != nil {
				log.Error("Error with docker runtime collection: ", err.Error())
			} else {
				filesToZip = append(filesToZip, dockerFilesToZip...)
			}

		case "kubernetes":
			if k8sFilesToZip, err := runKubernetes(); err != nil {
				log.Error("Error with VM runtime collection: ", err.Error())
			} else {
				filesToZip = append(filesToZip, k8sFilesToZip...)
			}
		case "vm":
			if vmFilesToZip, err := runVM(); err != nil {
				log.Error("Error with VM runtime collection: ", err.Error())
			} else {
				filesToZip = append(filesToZip, vmFilesToZip...)
			}
		default:
			log.Error("Runtime not found:", rType)
		}

		if os.Getenv("DISABLE_KDD") != "" {
			disableKDDCollection = (os.Getenv("DISABLE_KDD") == "true")
		}

		if disableKDDCollection && createWorkspaceConfigDumps {
			log.Info("Cannot create workspaces dumps when KDD collection is disabled")
		}

		if !disableKDDCollection {
			log.Info("KDD collection is enabled")

			if kddFilesToZip, err := getKDD(); err != nil {
				log.Error("Error with KDD collection: ", err.Error())
				//return err
			} else {
				filesToZip = append(filesToZip, kddFilesToZip...)
			}
		}

		log.Info("Writing tar.gz output")

		err := writeFiles(filesToZip)

		if err != nil {
			log.Error("Error writing tar.gz file: ", err.Error())
		}

		return nil
	},
}

var (
	defaultKongImageList = []string{"kong-gateway", "kubernetes-ingress-controller", "kuma-dp", "kuma-cp", "kuma-init"}
)

func init() {
	rootCmd.AddCommand(collectCmd)
	collectCmd.PersistentFlags().StringVarP(&rType, "runtime", "r", "", "Runtime to extract logs from (kubernetes or docker). Runtime is auto detected if omitted.")
	collectCmd.PersistentFlags().StringSliceVarP(&kongImages, "target-images", "i", defaultKongImageList, `Override default gateway/mesh images to scrape logs from. Default: "kong-gateway","kubernetes-ingress-controller","kuma-dp","kuma-cp","kuma-init"`)
	collectCmd.PersistentFlags().StringSliceVarP(&deckHeaders, "rbac-header", "H", nil, "RBAC header required to contact the admin-api.")
	collectCmd.PersistentFlags().StringVarP(&kongAddr, "kong-addr", "a", "http://localhost:8001", "The address to reach the admin-api of the Kong instance in question.")
	collectCmd.PersistentFlags().BoolVarP(&createWorkspaceConfigDumps, "dump-workspace-configs", "d", false, "Deck dump workspace configs to yaml files. Default: false. NOTE: Will not work if --disable-kdd=true")
	collectCmd.PersistentFlags().StringSliceVarP(&targetPods, "target-pods", "p", nil, "CSV list of pod names to target when extracting logs. Default is to scan all running pods for Kong images.")
	collectCmd.PersistentFlags().StringVar(&logsSinceDocker, "docker-since", "", "Return logs newer than a relative duration like 5s, 2m, or 3h. Used with docker runtime only. Will override --line-limit if set.")
	collectCmd.PersistentFlags().Int64Var(&logsSinceSeconds, "k8s-since-seconds", 0, "Return logs newer than the seconds past. Used with K8s runtime only. Will override --line-limit if set.")
	collectCmd.PersistentFlags().Int64Var(&lineLimit, "line-limit", LineLimitDefault, "Return logs with this amount of lines retrieved. Defaults to 1000 lines. Used with all runtimes as a default. --k8s-since-seconds and --docker-since will both override this setting.")
	collectCmd.PersistentFlags().StringVarP(&prefixDir, "prefix-dir", "k", "/usr/local/kong", "The path to your prefix directory for determining VM log locations. Default: /usr/local/kong")
	collectCmd.PersistentFlags().BoolVarP(&disableKDDCollection, "disable-kdd", "q", false, "Disable KDD config collection. Default: false.")
	collectCmd.PersistentFlags().StringSliceVarP(&strToRedact, "redact-logs", "R", nil, "CSV list of terms to redact during log extraction.")
}

func formatJSON(data []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", "    ")
	if err == nil {
		return out.Bytes(), err
	}
	return data, nil
}

func guessRuntime() (string, error) {
	log.Info("Trying to guess runtime...")
	var errList []string
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		errList = append(errList, err.Error())
	}

	_, err = cli.ServerVersion(ctx)

	//log.Info("Docker Version:", version.Arch)

	if err != nil {
		errList = append(errList, err.Error())
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})

	if err != nil {
		errList = append(errList, err.Error())
	}

	var kongContainers []types.Container

	for _, container := range containers {
		for _, i := range kongImages {
			if strings.Contains(container.Image, i) {
				kongContainers = append(kongContainers, container)
			}
		}
	}

	if len(kongContainers) > 0 {
		log.Info("Docker found")
		return Docker, nil
	}

	var kongK8sPods []string

	kubeClient, err := createClient()

	if err != nil {
		errList = append(errList, err.Error())

	} else {
		pl, err := kubeClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})

		if err != nil {
			errList = append(errList, err.Error())
		} else {
			for _, p := range pl.Items {
				for _, c := range p.Spec.Containers {
					//for _, i := range append(kongImages, meshImages...) {
					for _, i := range kongImages {
						if strings.Contains(c.Image, i) {
							kongK8sPods = append(kongK8sPods, p.Name)
						}
					}
				}
			}

			if len(kongK8sPods) > 0 {
				log.Info("Kubernetes found")
				return Kubernetes, nil
			}
		}
	}

	//If environment files exist, then VM install
	if _, err := os.Stat("/usr/local/kong/.kong_env"); err == nil {
		prefixDir = "/usr/local/kong"
		log.Info("VM found")
		return VM, nil
	} else {
		errList = append(errList, err.Error())

		//try /KONG_PREFIX
		if _, err := os.Stat("/KONG_PREFIX/.kong_env"); err == nil {
			prefixDir = "/KONG_PREFIX"
			log.Info("VM found")
			return VM, nil
		} else {
			errList = append(errList, err.Error())
		}
	}

	return "", fmt.Errorf(strings.Join(errList, "\n"))
}

func runDocker() ([]string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error("Unable to create docker api client")
		return nil, err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Error("Unable to get container list from docker api", err.Error())
		return nil, err
	}

	log.Info("Found: ", len(containers), " containers running")

	var kongContainers []types.Container

	for _, container := range containers {
		for _, i := range kongImages {
			if strings.Contains(container.Image, i) {
				kongContainers = append(kongContainers, container)
			}
		}
	}

	var filesToZip []string

	for _, c := range kongContainers {
		_, b, err := cli.ContainerInspectWithRaw(ctx, c.ID, false)
		if err != nil {
			log.Error("Unable to inspect container:", err.Error())
			continue
			//return err
		}

		prettyJSON, err := formatJSON(b)
		if err != nil {
			log.Error("Unable to format JSON:", err)
			continue
			//return err
		}

		sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(c.Image, ":", "/"), "/", "-")
		sanitizedContainerName := strings.ReplaceAll(c.Names[0], "/", "")
		inspectFilename := fmt.Sprintf("%s-%s.json", sanitizedContainerName, sanitizedImageName)
		inspectFile, err := os.Create(inspectFilename)
		defer inspectFile.Close()

		if err != nil {
			log.Error("Unable to create inspection file:", err)
			continue
			//return err
		} else {
			log.Infof("writing docker inspect data for %s", sanitizedContainerName)
			_, err = io.Copy(inspectFile, bytes.NewReader(prettyJSON))
			if err != nil {
				log.Error("Unable to write inspect file:", err.Error())
				continue
				//return err
			} else {
				err = inspectFile.Close()
				if err != nil {
					log.Error("Unable to close inspect file:", err.Error())
					continue
					//return err
				} else {
					filesToZip = append(filesToZip, inspectFilename)
				}
			}
		}

		logsFilename := fmt.Sprintf("%s-%s.log", sanitizedContainerName, sanitizedImageName)
		logFile, err := os.Create(logsFilename)
		defer logFile.Close()

		if err != nil {
			log.Error("Unable to create container log file:", err.Error())
			continue
			//return err
		} else {

			if os.Getenv("DOCKER_LOGS_SINCE") != "" {
				logsSinceDocker = os.Getenv("DOCKER_LOGS_SINCE")
			}

			options := types.ContainerLogsOptions{}

			if logsSinceDocker != "" {
				options = types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Since: logsSinceDocker, Details: true}
			} else {
				strLineLimit := strconv.Itoa(int(lineLimit))
				options = types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: strLineLimit, Details: true}
			}

			logs, err := cli.ContainerLogs(ctx, c.ID, options)

			defer logs.Close()
			if err != nil {
				log.Error("Unable to retrieve container logs:", err)
				continue
				//return err
			} else {
				log.Infof("writing docker logs data for %s", sanitizedContainerName)

				buf := bufio.NewScanner(logs)

				for buf.Scan() {

					bytes := buf.Bytes()
					var sanitizedBytes []byte

					if len(bytes) > 7 {

						B1 := bytes[0]
						B2 := bytes[1]
						B3 := bytes[2]
						B4 := bytes[3]
						B5 := bytes[4]
						B6 := bytes[5]
						B7 := bytes[6]

						zeroByte := byte(0)

						//Remove header bytes from the docker cli log scans if they match specific patterns.
						if B1 == byte(50) && B2 == byte(48) && B3 == byte(50) && B4 == byte(50) && B5 == byte(47) && B6 == byte(48) && B7 == byte(54) {
							sanitizedBytes = bytes[8:]
						} else if (B1 == byte(2) || B1 == byte(1)) && B2 == zeroByte && B3 == zeroByte && B4 == zeroByte && B5 == zeroByte && B6 == zeroByte && (B7 == zeroByte || B7 == byte(1)) {
							sanitizedBytes = bytes[8:]
						} else {
							sanitizedBytes = bytes
						}
					}
					sanitizedLogLine := string(sanitizedBytes) + "\n"

					if len(strToRedact) > 0 {
						sanitizedLogLine = analyseLogLineForRedaction(sanitizedLogLine + "\n")
					}

					_, err = io.Copy(logFile, strings.NewReader(sanitizedLogLine))
					if err != nil {
						log.Error("Unable to write container logs: ", err)
						continue
						//return err
					}
				}

				err = logFile.Close()
				if err != nil {
					log.Error("Unable to close container logs: ", err)
					continue
					//return err
				} else {
					filesToZip = append(filesToZip, logsFilename)
				}

			}
		}

	}

	return filesToZip, nil
}

func analyseLogLineForRedaction(line string) string {
	returnLine := strings.ToLower(line)

	for _, v := range strToRedact {
		if strings.Contains(returnLine, strings.ToLower(v)) {
			returnLine = strings.ReplaceAll(returnLine, strings.ToLower(v), "<REDACTED>")
		}
	}

	return returnLine
}

func getKDD() ([]string, error) {

	//Responsible for creating the KDD.json object

	//Generate KDD file

	//Generate Workspace Dumps

	var summaryInfo SummaryInfo
	var finalResponse = make(map[string]interface{})
	var filesToZip []string

	if os.Getenv("KONG_ADDR") != "" {
		kongAddr = os.Getenv("KONG_ADDR")
	}

	if os.Getenv("RBAC_HEADER") != "" {
		deckHeaders = strings.Split(os.Getenv("RBAC_HEADER"), ",")
	}

	client, err := utils.GetKongClient(utils.KongClientConfig{
		Address:       kongAddr,
		TLSSkipVerify: true,
		Debug:         false,
		Headers:       deckHeaders,
	})

	if err != nil {
		return nil, err
	}

	root, err := client.RootJSON(context.Background())

	if err != nil {
		return nil, err
	}

	rootConfig, err = objx.FromJSON(string(root))

	if err != nil {
		return nil, err
	}

	status, _ := getEndpoint(client, "/status")

	workspaces, err := getWorkspaces(client)

	if err != nil {
		return nil, err
	}

	licenseReport, err := getEndpoint(client, "/license/report")

	if err != nil {
		return nil, err
	}

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

	finalResponse["root_config"] = rootConfig
	finalResponse["status"] = status
	finalResponse["license_report"] = licenseReport

	//Incomplete data as yet, but saving what we've collected so far incase of error during workspace iteration
	finalResponse["summary_info"] = summaryInfo

	if os.Getenv("DUMP_WORKSPACE_CONFIGS") != "" {
		log.Info("Var:", os.Getenv("DUMP_WORKSPACE_CONFIGS"))
		createWorkspaceConfigDumps = (os.Getenv("DUMP_WORKSPACE_CONFIGS") == "true")
	}

	for _, ws := range workspaces.Data {

		client.SetWorkspace(ws.Name)

		d, err := dump.Get(context.Background(), client, dump.Config{
			RBACResourcesOnly: false,
			SkipConsumers:     false,
		})

		if err != nil {
			log.Error("Error getting workspace data for: ", ws.Name)
			log.Error(err.Error(), " continuing to next workspace")
		} else {
			summaryInfo.TotalConsumerCount += len(d.Consumers)
			summaryInfo.TotalServiceCount += len(d.Services)
			summaryInfo.TotalRouteCount += len(d.Routes)
			summaryInfo.TotalPluginCount += len(d.Plugins)
			summaryInfo.TotalTargetCount += len(d.Targets)
			summaryInfo.TotalUpstreamCount += len(d.Upstreams)

			if ws.Config.Portal {
				summaryInfo.TotalEnabledDevPortalCount += 1
			}

			if createWorkspaceConfigDumps {
				ks, err := state.Get(d)
				if err != nil {
					log.Errorf("building Kong dump state: %w", err)
				}
				err = file.KongStateToFile(ks, file.WriteConfig{
					Filename:   ws.Name + "-kong-dump.yaml",
					FileFormat: file.YAML,
				})
				if err != nil {
					log.Errorf("building Kong dump file: %w", err)
				} else {
					log.Info("Successfully dumped workspace: ", ws.Name)
					filesToZip = append(filesToZip, ws.Name+"-kong-dump.yaml")
				}
			}
		}
	}

	//Add the full info now we know we have it all
	finalResponse["summary_info"] = summaryInfo

	jsonBytes, err := json.Marshal(finalResponse)

	if err != nil {
		log.Error("Error marshalling json:", err)
	}

	err = os.WriteFile("KDD.json", jsonBytes, 0644)
	if err != nil {
		log.Fatal("Error writing KDD.json")
		return filesToZip, err
	} else {
		filesToZip = append(filesToZip, "KDD.json")
	}

	//Clear workspace slice at this point if not writing dump files, otherwise app will try and add files to zip

	return filesToZip, nil
}

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

func getObjx(req *http.Request, client *kong.Client) (objx.Map, error) {
	resp, err := client.DoRAW(context.Background(), req)

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	strBody := string(body)

	oReturn, err := objx.FromJSON(strBody)

	if err != nil {
		return nil, err
	}

	return oReturn, nil
}

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

func runKubernetes() ([]string, error) {
	log.Info("Running Kubernetes")
	ctx := context.Background()
	var kongK8sPods []corev1.Pod
	var filesToZip []string

	kubeClient, err := createClient()
	if err != nil {
		log.Error("Unable to create k8s client")
		return nil, err
	}

	pl, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{})

	if os.Getenv("TARGET_PODS") != "" {
		targetPods = strings.Split(os.Getenv("TARGET_PODS"), ",")
	}

	//To keep track of whether a particular pod has been added already. As a pod with an ingress-controller image and a kong-gateway image will be added twice to the kongK8sPods slice
	foundPod := make(map[string]bool)

	for _, p := range pl.Items {
		if len(targetPods) > 0 {
			for _, podName := range targetPods {
				if strings.ToLower(podName) == strings.ToLower(p.Name) {
					for _, c := range p.Spec.Containers {
						for _, i := range kongImages {
							//log.Info("Checking pod: ", p.Name, " for image:", i)
							if strings.Contains(c.Image, i) {
								if !foundPod[p.Name] {
									log.Info("Appending: ", p.Name, " with container count: ", len(p.Spec.Containers))
									kongK8sPods = append(kongK8sPods, p)
									foundPod[p.Name] = true
								}
							}
						}
					}
				}
			}
		} else {
			for _, c := range p.Spec.Containers {
				for _, i := range kongImages {
					//log.Info("Checking pod: ", p.Name, " for image:", i)
					if strings.Contains(c.Image, i) {
						if !foundPod[p.Name] {
							log.Info("Appending: ", p.Name, " with container count: ", len(p.Spec.Containers))
							kongK8sPods = append(kongK8sPods, p)
							foundPod[p.Name] = true
						}
					}
				}
			}
		}
	}

	if len(kongK8sPods) > 0 {
		logFilenames, err := writePodDetails(ctx, kubeClient, kongK8sPods)

		if err != nil {
			log.Error("There was an error writing pod details: ", err.Error())
		} else {
			filesToZip = append(filesToZip, logFilenames...)
		}

	} else {
		log.Info("No pods with the appropriate container images found in cluster")
	}

	return filesToZip, nil
}

func createAndWriteLogFile(initialLogName string, contents string) (string, error) {
	hostname, _ := os.Hostname()

	logName := fmt.Sprintf(hostname+"_"+initialLogName+"-%s.log", time.Now().Format("2006-01-02-15-04-05"))

	if logFile, err := os.Create(logName); err != nil {
		log.Error("Cannot create " + initialLogName + " log file.")
		return "", err
	} else {

		defer logFile.Close()

		if _, err = io.Copy(logFile, strings.NewReader(contents)); err != nil {
			log.Error("Unable to write contents to " + initialLogName)
			return "", err
		}

		logFile.Close()
	}

	return logName, nil
}

func runVM() ([]string, error) {
	log.Info("Running in VM mode.")

	if lineLimit == LineLimitDefault {
		log.Info("Using default line limit value of ", LineLimitDefault)
	}

	var filesToZip []string

	if prefixDir != "" {
		log.Info("Reading environment file...")

		d, err := os.ReadFile(prefixDir + "/.kong_env")

		if err != nil {
			log.Error("Error reading config file")
			return nil, err
		}

		configSummary, err := os.Create("vm-kong-env.txt")

		if err != nil {
			log.Error("Error creating vm-kong-env.txt")
			return nil, err
		}

		log.Info("Writing kong environment data...")

		if _, err = io.Copy(configSummary, bytes.NewReader(d)); err != nil {
			log.Error(err)
		}

		if configSummary.Close(); err == nil {
			filesToZip = append(filesToZip, "vm-kong-env.txt")
		} else {
			log.Error("Error closing vm-kong-env.txt")
			return nil, err
		}

		//Config keys that have the paths to log files that need extracting
		configKeys := []string{"admin_access_log", "admin_error_log", "proxy_access_log", "proxy_error_log"}

		for _, v := range configKeys {
			logName := collectAndLimitLog(string(d), v)
			if logName != "" {
				filesToZip = append(filesToZip, logName)
			}
		}
	} else {
		log.Info("No prefix directory set. The prefix parameter must be set for VM log extraction.")
	}

	return filesToZip, nil
}

func collectAndLimitLog(envars, configKey string) string {

	splitEnvars := strings.Split(envars, "\n")

	for _, configLine := range splitEnvars {
		if strings.Contains(configLine, configKey) {
			logPath := getConfigValue(configLine)

			var logLines []string

			if logPath[:4] == "logs" {
				log.Info("Using prefix for log path: ", prefixDir+"/"+logPath)
				logPath = prefixDir + "/" + logPath
			}

			//Get file length in bytes
			logLength := getFileLength(logPath)

			log.Info("Log file length in bytes:", logLength)

			done := false

			if logLength > 0 {

				//Read bytes 1 by 1 until a new line character is found, then all previous bytes become a line
				if logFile, err := os.Open(logPath); err != nil {
					log.Error("Error opening log: ", err.Error())
				} else {

					defer logFile.Close()

					singleByteBuffer := make([]byte, 1)
					var singleLineBytes []byte
					linesProcessed := int64(0)
					bytesProcessed := int64(0)
					success := false

					for {
						if done {
							break
						}

						if _, err := logFile.ReadAt(singleByteBuffer, logLength-bytesProcessed-1); err != nil && err != io.EOF {
							log.Error("Unable to read a byte from: ", logPath)
							log.Error(err.Error())
							done = true
						} else if err == io.EOF {
							log.Info("Hit the end of the file.")

							done = true

						} else {
							lastReadByte := singleByteBuffer[0]
							bytesProcessed += 1
							//Check for /n byte. No support for /r/n yet.
							if lastReadByte == 10 {

								for i, j := 0, len(singleLineBytes)-1; i < j; i, j = i+1, j-1 {
									singleLineBytes[i], singleLineBytes[j] = singleLineBytes[j], singleLineBytes[i]
								}

								logLines = append(logLines, string(singleLineBytes[:]))

								singleLineBytes = make([]byte, 0)
								linesProcessed += 1
								success = true
							} else {
								singleLineBytes = append(singleLineBytes, lastReadByte)
							}

							if linesProcessed == lineLimit {
								done = true
							}

						}
					}

					if success {

						//Flip the lines as they are read backwards
						for i, j := 0, len(logLines)-1; i < j; i, j = i+1, j-1 {
							logLines[i], logLines[j] = logLines[j], logLines[i]
						}

						sanitizedLogLines := logLines

						if len(strToRedact) > 0 {
							for i, v := range logLines {
								sanitizedLogLines[i] = analyseLogLineForRedaction(v)
							}
						}

						concatLogs := fmt.Sprintf(strings.Join(sanitizedLogLines, "\n"))

						if len(concatLogs) > 0 {
							if logName, err := createAndWriteLogFile(configKey, concatLogs); err != nil {
								log.Error("Error creating or writing log file: ", err.Error())
							} else {
								log.Info(configKey+" log successfully created: ", logName)

								return logName
							}
						} else {
							log.Info("Skipping creation of " + configKey + " logs as the log either does not exist or has no length.")
						}

						log.Info("Finished reading Log. Lines written: ", len(sanitizedLogLines))
					}
				}
			} else {
				log.Info("Log file has no length, continuing...")
			}
		}
	}

	return ""
}

func getConfigValue(entry string) string {
	aEntry := strings.Split(entry, "=")
	return strings.Trim(aEntry[1], " ")
}

//Returns total length of byte array
func getFileLength(logPath string) int64 {
	log.Info("Getting log length for: ", logPath)
	size := int64(0)

	if fileInfo, err := os.Stat(logPath); err != nil {
		log.Error("Error reading file info ", err.Error())
	} else {
		size = fileInfo.Size()
		log.Info(logPath, " length is: ", size)
	}

	return size
}

func createClient() (kubernetes.Interface, error) {
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})

	clientConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error finding Kubernetes API server config in --kubeconfig, $KUBECONFIG, or in-cluster configuration")
	}

	clientSet, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create a client: %v", err)
	}

	return clientSet, nil
}

func writePodDetails(ctx context.Context, clientSet kubernetes.Interface, podList []corev1.Pod) ([]string, error) {
	var logFilenames []string
	for _, pod := range podList {
		p, err := clientSet.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			log.Error(err)
			//return logFilenames, err
			continue
		}

		log.Info("Working on Pod: ", p.Name, " in namespace: ", p.Namespace)

		//for _, container := range append(p.Spec.InitContainers, p.Spec.Containers...) {
		for _, container := range p.Spec.Containers {

			relevantImage := false

			for _, i := range kongImages {
				//log.Info("Checking container: ", container.Name, " for image: ", i)
				if strings.Contains(container.Image, i) {
					relevantImage = true
				}
			}

			if relevantImage {
				log.Info("Working on container: ", container.Name)

				if os.Getenv("K8S_LOGS_SINCE_SECONDS") != "" {
					logsSinceSeconds, err = strconv.ParseInt(os.Getenv("K8S_LOGS_SINCE_SECONDS"), 10, 64)
				}

				//options := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Since: logsSinceSeconds, Details: true}
				podLogOpts := corev1.PodLogOptions{}

				if logsSinceSeconds > 0 {
					podLogOpts = corev1.PodLogOptions{Container: container.Name, SinceSeconds: &logsSinceSeconds}
				} else {
					podLogOpts = corev1.PodLogOptions{Container: container.Name, TailLines: &lineLimit}
				}

				//podLogOpts.TailLines = &[]int64{int64(100)}[0]

				podLogs, err := clientSet.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts).Stream(ctx)

				if err != nil {
					log.Error("Error retrieving pod logs:", err.Error())
					//return logFilenames, err
					continue
				}

				sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(container.Image, ":", "/"), "/", "-")
				logsFilename := fmt.Sprintf("%s-%s.log", pod.Name, sanitizedImageName)

				logFile, err := os.Create(logsFilename)
				defer logFile.Close()

				if err != nil {
					log.Error("Error creating log file:", err.Error())
					continue
				}

				if len(strToRedact) > 0 {
					buf := bufio.NewScanner(podLogs)

					for buf.Scan() {

						bytes := buf.Bytes()

						sanitizedLogLine := analyseLogLineForRedaction(string(bytes) + "\n")

						_, err = io.Copy(logFile, strings.NewReader(sanitizedLogLine))
						if err != nil {
							log.Error("Unable to write container logs: ", err)
							continue
							//return err
						}
					}
				} else {
					_, err = io.Copy(logFile, podLogs)
					if err != nil {
						log.Error(err)
						//return logFilenames, err
						continue
					}
				}

				err = podLogs.Close()
				if err != nil {
					log.Error(err)
					//return logFilenames, err
					continue
				}

				err = logFile.Close()
				if err != nil {
					log.Error(err)
					//return logFilenames, err
					continue
				}

				logFilenames = append(logFilenames, logsFilename)
			}
		}

		podDefFileName := fmt.Sprintf("%s.yaml", p.Name)
		podDefFile, err := os.Create(podDefFileName)
		defer podDefFile.Close()

		if err != nil {
			log.Error(err)
			continue
		}

		buf := bytes.NewBufferString("")
		pod.TypeMeta = metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		}
		scheme := runtime.NewScheme()
		serializer := kjson.NewSerializerWithOptions(kjson.DefaultMetaFactory, scheme, scheme, kjson.SerializerOptions{
			Pretty: true,
			Yaml:   true,
			Strict: true,
		})
		err = serializer.Encode(&pod, buf)

		if err != nil {
			log.Println(err)
			continue
		}

		_, err = io.Copy(podDefFile, buf)
		if err != nil {
			log.Println(err)
			continue
		}

		logFilenames = append(logFilenames, podDefFileName)
	}
	return logFilenames, nil
}

func writeFiles(filesToWrite []string) error {
	output, err := os.Create(fmt.Sprintf("%s-support.tar.gz", time.Now().Format("2006-01-02-15-04-05")))
	if err != nil {
		return err
	}
	defer func() {
		if tempErr := output.Close(); tempErr != nil {
			err = tempErr
		}
	}()

	// Create the archive and write the output to the "out" Writer
	gw := gzip.NewWriter(output)
	defer func() {
		if tempErr := gw.Close(); tempErr != nil {
			err = tempErr
		}
	}()
	tw := tar.NewWriter(gw)
	defer func() {
		if tempErr := tw.Close(); tempErr != nil {
			err = tempErr
		}
	}()

	// Iterate over files and add them to the tar archive
	for _, file := range filesToWrite {
		err := addToArchive(tw, file)
		if err != nil {
			return err
		}
	}

	log.Info("Diagnostics have been written to: ", output.Name())

	return nil
}

func addToArchive(tw *tar.Writer, filename string) error {
	// Open the file which will be written into the archive
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() {
		if tempErr := file.Close(); tempErr != nil {
			err = tempErr
		}
	}()

	// Get FileInfo about our file providing file size, mode, etc.
	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Create a tar Header from the FileInfo data
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}

	// Use full path as name (FileInfoHeader only takes the basename)
	// If we don't do this the directory structure would
	// not be preserved
	// https://golang.org/src/archive/tar/common.go?#L626
	header.Name = filename

	// Write file header to the tar archive
	err = tw.WriteHeader(header)
	if err != nil {
		return err
	}

	// Copy file content to tar archive
	_, err = io.Copy(tw, file)
	if err != nil {
		return err
	}

	return nil
}

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
}

type CustomMessage struct {
	Message string `json:"message"`
}
