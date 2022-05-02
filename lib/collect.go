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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/kong/deck/dump"
	"github.com/kong/deck/file"
	"github.com/kong/deck/state"
	"github.com/kong/deck/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	Docker     = "docker"
	Kubernetes = "kubernetes"
	VM         = "vm"
)

var (
	rType       string
	kongImages  = []string{"kong-gateway", "kubernetes-ingress-controller"}
	meshImages  = []string{"kuma-dp", "kuma-cp", "kuma-init"}
	deckHeaders []string
)

//var (
// 	defaultKongImageList = []string{"kong-gateway", "kubernetes-ingress-controller"}
// 	defaultMeshImageList = []string{"kuma-dp", "kuma-cp", "kuma-init"}
// )

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

func Execute() error {
	rType = os.Getenv("KONG_RUNTIME")

	if rType == "" {
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
		fmt.Println("Not supported yet")
	default:
		fmt.Println("error")
	}
	return nil
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

					sanitizedBytes := buf.Bytes()[8:]

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

		if os.Getenv("KONG_ADDR") != "" {
			err = getKongDump(os.Getenv("KONG_ADDR"), "kong-dump.yaml")
			if err != nil {
				log.Error("Kong dump unsuccessful: ", err)
				//return err
			} else {
				filesToZip = append(filesToZip, "kong-dump.yaml")
			}
		} else {
			log.Println("KONG_ADDR environment variable not set, cannot get dump of Kong config.")
		}

	}

	log.Debugf("Writing tar.gz output")
	err = writeFiles(filesToZip)
	if err != nil {
		return err
	}

	return nil
}

func getKongDump(endpoint, fileToWrite string) error {
	if deckHeaders == nil {
		if os.Getenv("DECK_HEADERS") != "" {
			deckHeaders = strings.Split(os.Getenv("DECK_HEADERS"), ",")
		}
	}
	client, err := utils.GetKongClient(utils.KongClientConfig{
		Address:       endpoint,
		TLSSkipVerify: true,
		Debug:         false,
		Headers:       deckHeaders,
	})

	if err != nil {
		return err
	}

	d, err := dump.Get(context.Background(), client, dump.Config{
		RBACResourcesOnly: false,
		SkipConsumers:     false,
	})
	if err != nil {
		return err
	}
	ks, err := state.Get(d)
	if err != nil {
		return fmt.Errorf("building Kong dump state: %w", err)
	}
	err = file.KongStateToFile(ks, file.WriteConfig{
		Filename:   fileToWrite,
		FileFormat: file.YAML,
	})
	if err != nil {
		return fmt.Errorf("building Kong dump file: %w", err)
	}
	return nil
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
				if strings.Contains(c.Image, i) {
					if !foundPod[p.Name] {
						log.Debug("Appending: ", p.Name, " with containers: ", len(p.Spec.Containers))
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

		if os.Getenv("KONG_ADDR") != "" {
			log.Info("Attempting to connect to admin-api on: ", os.Getenv("KONG_ADDR"))

			err = getKongDump(os.Getenv("KONG_ADDR"), "kong-dump.yaml")
			if err != nil {
				log.Error("Kong dump unsuccessful: ", err)
				//return err
			} else {
				filesToZip = append(filesToZip, "kong-dump.yaml")
			}
		} else {
			log.Info("KONG_ADDR environment variable not set, cannot get dump of Kong config.")
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
