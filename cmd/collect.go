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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
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
	"github.com/ssgelm/cookiejarparser"
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
	Docker     = "docker"
	Kubernetes = "kubernetes"
	VM         = "vm"
)

var (
	rType                      string
	kongImages                 []string
	meshImages                 []string
	deckHeaders                []string
	clientTimeout              time.Duration
	rootConfig                 objx.Map
	kongAddr                   string
	createWorkspaceConfigDumps bool
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
	Use:   "collect",
	Short: "A brief description of your collect",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:
Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRun: toggleDebug,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rType == "" {
			rType = os.Getenv("KONG_RUNTIME")
		}

		if os.Getenv("LOG_LEVEL") == "debug" {
			log.SetLevel(5)
		}

		if rType == "" {
			log.Debug("No runtime detected, attempting to guess runtime...")
			runtime, err := guessRuntime()
			if err != nil {
				return err
			}
			rType = runtime
		}

		switch rType {
		case "docker":
			return runDocker()
		case "kubernetes":
			return runKubernetes()
		case "vm":
			log.Warn("Not supported yet")
		default:
			log.Error("Runtime not found:", rType)
		}
		return nil
	},
}

var (
	defaultKongImageList = []string{"kong-gateway", "kubernetes-ingress-controller"}
	defaultMeshImageList = []string{"kuma-dp", "kuma-cp", "kuma-init"}
)

func init() {
	rootCmd.AddCommand(collectCmd)
	collectCmd.PersistentFlags().StringVarP(&rType, "runtime", "r", "", "runtime")
	collectCmd.PersistentFlags().StringSliceVarP(&kongImages, "gateway-images", "g", defaultKongImageList, "List of gateway image names to look for")
	collectCmd.PersistentFlags().StringSliceVarP(&meshImages, "mesh-images", "m", defaultMeshImageList, "List of mesh image names to look for")
	collectCmd.PersistentFlags().StringSliceVarP(&deckHeaders, "deck-headers", "H", nil, "Headers associated")
	collectCmd.PersistentFlags().StringVarP(&kongAddr, "kong-addr", "", "http://localhost:8001", "kong addr")
	collectCmd.PersistentFlags().BoolVarP(&createWorkspaceConfigDumps, "config-dump", "c", false, "config dump")
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
	log.Debug("Trying to guess runtime...")
	var errList []string
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
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
		log.Debug("found Docker")
		return Docker, nil
	}

	var kongK8sPods []string

	kubeClient, err := createClient()
	pl, err := kubeClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})
	for _, p := range pl.Items {
		for _, c := range p.Spec.Containers {
			for _, i := range append(kongImages, meshImages...) {
				if strings.Contains(c.Image, i) {
					kongK8sPods = append(kongK8sPods, p.Name)
				}
			}
		}
	}

	if len(kongK8sPods) > 0 {
		log.Debug("found Kubernetes")
		return Kubernetes, nil
	}

	return "", fmt.Errorf(strings.Join(errList, "\n"))
}

func runDocker() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error("Unable to create docker api client")
		return err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Error("Unable to get container list from docker api")
		return err
	}

	log.Debug("Found: ", len(containers), " containers running")

	var kongContainers []types.Container

	for _, container := range containers {
		for _, i := range append(kongImages, meshImages...) {
			if strings.Contains(container.Image, i) {
				kongContainers = append(kongContainers, container)
			}
		}
	}

	var filesToZip []string

	for _, c := range kongContainers {
		j, b, err := cli.ContainerInspectWithRaw(ctx, c.ID, false)
		if err != nil {
			log.Error("Unable to inspect container:", err)
			continue
			//return err
		}

		prettyJSON, err := formatJSON(b)
		if err != nil {
			log.Error("Unable to format JSON:", err)
			continue
			//return err
		}

		env := make(map[string]string)

		for _, v := range j.Config.Env {
			s := strings.SplitN(v, "=", 2)
			env[s[0]] = s[1]
		}

		sum := createSummary(env)
		sum.Platform = "Docker"

		sumBytes := []byte(fmt.Sprintf(
			`Environment Summary:
			- Platform: %s
			- Kong Version: %s
			- Vitals: %s
			- Portal: %s
			- DB Mode: %s
			`, sum.Platform, sum.Version, sum.Vitals, sum.Portal, sum.DBMode))

		summaryFile, err := os.Create("Summary.txt")
		defer summaryFile.Close()

		if err != nil {
			log.Error("Unable to create summary file:", err)
			continue
			//return err
		} else {
			log.Debug("writing summary data")
			_, err = io.Copy(summaryFile, bytes.NewReader(sumBytes))
			if err != nil {
				log.Error("Unable to write to summary file:", err)
				continue
				//return err
			} else {
				err = summaryFile.Close()
				if err != nil {
					log.Error("Unable to close summary file:", err)
					continue
					//return err
				} else {
					filesToZip = append(filesToZip, "Summary.txt")
				}
			}
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
			log.Debugf("writing docker inspect data for %s", sanitizedContainerName)
			_, err = io.Copy(inspectFile, bytes.NewReader(prettyJSON))
			if err != nil {
				log.Error("Unable to write inspect file:", err)
				continue
				//return err
			} else {
				err = inspectFile.Close()
				if err != nil {
					log.Error("Unable to close inspect file:", err)
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
			log.Error("Unable to create container log file:", err)
			continue
			//return err
		} else {
			options := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
			logs, err := cli.ContainerLogs(ctx, c.ID, options)

			defer logs.Close()
			if err != nil {
				log.Error("Unable to retrieve container logs:", err)
				continue
				//return err
			} else {
				log.Debugf("writing docker logs data for %s", sanitizedContainerName)

				buf := bufio.NewScanner(logs)

				for buf.Scan() {

					bytes := buf.Bytes()
					var sanitizedBytes []byte

					if len(bytes) > 7 {
						sanitizedBytes = buf.Bytes()[8:]
					} else {
						sanitizedBytes = buf.Bytes()[7:]
					}

					_, err = io.Copy(logFile, strings.NewReader(string(sanitizedBytes)+"\n"))
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

		ws_names, err := getKongDump()

		if err != nil {
			log.Error("Kong dump unsuccessful: ", err)
			//return err
		} else {
			for _, name := range ws_names {
				filesToZip = append(filesToZip, name+"-kong-dump.yaml")
			}

			filesToZip = append(filesToZip, "KDD.json")
		}

	}

	log.Debugf("Writing tar.gz output")
	err = writeFiles(filesToZip)
	if err != nil {
		return err
	}

	return nil
}

func GetClient(opt utils.KongClientConfig) (*http.Client, string, error) {
	var tlsConfig tls.Config
	if opt.TLSSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if opt.TLSServerName != "" {
		tlsConfig.ServerName = opt.TLSServerName
	}

	if opt.TLSCACert != "" {
		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM([]byte(opt.TLSCACert))
		if !ok {
			return nil, "", fmt.Errorf("failed to load TLSCACert")
		}
		tlsConfig.RootCAs = certPool
	}

	if opt.TLSClientCert != "" && opt.TLSClientKey != "" {
		// Read the key pair to create certificate
		cert, err := tls.X509KeyPair([]byte(opt.TLSClientCert), []byte(opt.TLSClientKey))
		if err != nil {
			return nil, "", fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	clientTimeout = time.Duration(opt.Timeout) * time.Second
	c := opt.HTTPClient
	if c == nil {
		c = utils.HTTPClient()
	}
	defaultTransport := http.DefaultTransport.(*http.Transport)
	defaultTransport.TLSClientConfig = &tlsConfig
	c.Transport = defaultTransport
	sanitizedAddress := utils.CleanAddress(opt.Address)

	headers, err := parseHeaders(opt.Headers)
	if err != nil {
		return nil, "", fmt.Errorf("parsing headers: %w", err)
	}
	c = kong.HTTPClientWithHeaders(c, headers)

	//_, err := url.ParseRequestURI(address)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse kong address: %w", err)
	}
	// Add Session Cookie support if required
	if opt.CookieJarPath != "" {
		jar, err := cookiejarparser.LoadCookieJarFile(opt.CookieJarPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to initialize cookie-jar: %w", err)
		}
		c.Jar = jar
	}

	// kongClient, err := kong.NewClient(kong.String(url.String()), c)
	// if err != nil {
	// 	return nil, fmt.Errorf("creating client for Kong's Admin API: %w", err)
	// }
	// if opt.Debug {
	// 	kongClient.SetDebugMode(true)
	// 	kongClient.SetLogger(os.Stderr)
	// }
	// if opt.Workspace != "" {
	// 	kongClient.SetWorkspace(opt.Workspace)
	// }
	return c, sanitizedAddress, nil
}

func getKongDump() ([]string, error) {

	var summaryInfo SummaryInfo
	var finalResponse = make(map[string]interface{})

	endpoint := os.Getenv("KONG_ADDR")

	if endpoint == "" {
		endpoint = kongAddr
	}

	if os.Getenv("DECK_HEADERS") != "" {
		deckHeaders = strings.Split(os.Getenv("DECK_HEADERS"), ",")
	}

	client, err := utils.GetKongClient(utils.KongClientConfig{
		Address:       endpoint,
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

	var ws_names []string

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

	if os.Getenv("ENABLE_CONFIG_DUMP") != "" {
		createWorkspaceConfigDumps = (os.Getenv("ENABLE_CONFIG_DUMP") == "true")
	}

	for _, ws := range workspaces.Data {
		if createWorkspaceConfigDumps {
			ws_names = append(ws_names, ws.Name)
		}

		client.SetWorkspace(ws.Name)
		log.Debug("Workspace:", ws.Name)

		d, err := dump.Get(context.Background(), client, dump.Config{
			RBACResourcesOnly: false,
			SkipConsumers:     false,
		})
		if err != nil {
			return nil, err
		}

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
				return nil, fmt.Errorf("building Kong dump state: %w", err)
			}
			err = file.KongStateToFile(ks, file.WriteConfig{
				Filename:   ws.Name + "-kong-dump.yaml",
				FileFormat: file.YAML,
			})
			if err != nil {
				return nil, fmt.Errorf("building Kong dump file: %w", err)
			}
		}
	}

	//Add the full info now we know we have it all
	finalResponse["summary_info"] = summaryInfo

	jsonBytes, err := json.Marshal(finalResponse)

	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("KDD.json", jsonBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}

	//Clear workspace slice at this point if not writing dump files, otherwise app will try and add files to zip

	return ws_names, nil
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

func createSummary(env map[string]string) Summary {
	s := Summary{
		Version: "Unknown",
		Portal:  "off",
		Vitals:  "off",
		DBMode:  "off",
	}
	for k, v := range env {
		switch k {
		case "KONG_DATABASE":
			s.DBMode = v
		case "KONG_PORTAL":
			s.Portal = v
		case "KONG_VITALS":
			s.Vitals = v
		case "KONG_VERSION":
			s.Version = v
		default:
		}
	}

	return s
}

func runKubernetes() error {
	log.Debug("Running Kubernetes")
	ctx := context.Background()
	var kongK8sPods []corev1.Pod
	var filesToZip []string

	kubeClient, err := createClient()
	if err != nil {
		log.Error("Unable to create k8s client")
		return err
	}

	pl, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{})

	//To keep track of whether a particular pod has been added already. As a pod with an ingress-controller image and a kong-gateway image will be added twice to the kongK8sPods slice
	foundPod := make(map[string]bool)

	for _, p := range pl.Items {
		for _, c := range p.Spec.Containers {
			for _, i := range append(kongImages, meshImages...) {
				log.Debug("Checking pod:", p.Name, "for image:", i)
				if strings.Contains(c.Image, i) {
					if !foundPod[p.Name] {
						log.Debug("Appending: ", p.Name, " with container count: ", len(p.Spec.Containers))
						kongK8sPods = append(kongK8sPods, p)
						foundPod[p.Name] = true
					}
				}
			}
		}
	}

	if len(kongK8sPods) > 0 {
		logFilenames, err := writePodDetails(ctx, kubeClient, kongK8sPods)

		if err != nil {
			log.Error("There was an error writing pod details: ", err)
		} else {
			filesToZip = append(filesToZip, logFilenames...)
		}

		ws_names, err := getKongDump()
		if err != nil {
			log.Error("Kong dump unsuccessful: ", err)
			//return err
		} else {
			for _, name := range ws_names {
				filesToZip = append(filesToZip, name+"-kong-dump.yaml")
			}

			filesToZip = append(filesToZip, "KDD.json")
		}

		err = writeFiles(filesToZip)
		if err != nil {
			return err
		} else {

		}
	} else {
		log.Info("No Kong pods found in cluster")
	}

	return nil
}

func runVM() error {

	return nil
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

		log.Debug("Working on Pod: ", p.Name, " in namespace: ", p.Namespace)

		//for _, container := range append(p.Spec.InitContainers, p.Spec.Containers...) {
		for _, container := range p.Spec.Containers {
			log.Debug("Working on container: ", container.Name)

			podLogOpts := corev1.PodLogOptions{Container: container.Name}
			// podLogOpts.TailLines = &[]int64{int64(100)}[0]
			podLogs, err := clientSet.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts).Stream(ctx)
			if err != nil {
				log.Error(err)
				//return logFilenames, err
				continue
			}

			sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(container.Image, ":", "/"), "/", "-")
			logsFilename := fmt.Sprintf("%s-%s.log", pod.Name, sanitizedImageName)

			logFile, err := os.Create(logsFilename)
			defer logFile.Close()

			if err != nil {
				log.Error(err)
			}

			_, err = io.Copy(logFile, podLogs)
			if err != nil {
				log.Error(err)
				//return logFilenames, err
				continue
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

			env := make(map[string]string)

			if container.Name == "proxy" {
				for _, v := range container.Env {
					env[v.Name] = v.Value
				}
				sum := createSummary(env)
				sum.Platform = "Kubernetes"

				sumBytes := []byte(fmt.Sprintf(
					`Environment Summary:
					- Platform: %s
					- Kong Version: %s
					- Vitals: %s
					- Portal: %s
					- DB Mode: %s
					`, sum.Platform, sum.Version, sum.Vitals, sum.Portal, sum.DBMode))

				summaryFile, err := os.Create("Summary.txt")
				if err != nil {
					log.Error(err)
					//return logFilenames, err
					continue
				}

				log.Debug("Writing summary data for: ", container.Name)
				_, err = io.Copy(summaryFile, bytes.NewReader(sumBytes))
				if err != nil {
					log.Error(err)
					//return logFilenames, err
					continue
				}

				err = summaryFile.Close()
				if err != nil {
					log.Error(err)
					//return logFilenames, err
					continue
				}
				logFilenames = append(logFilenames, "Summary.txt")
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
