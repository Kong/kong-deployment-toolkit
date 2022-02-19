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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"os"
	"strings"

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
	rType      string
	kongImages []string
	meshImages []string
)

var (
	defaultKongImageList = []string{"kong-gateway", "kubernetes-ingress-controller"}
	defaultMeshImageList = []string{"kuma-dp", "kuma-cp", "kuma-init"}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mist",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRun: toggleDebug,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: func(cmd *cobra.Command, args []string) error {
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
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "verbose logging")
	rootCmd.PersistentFlags().StringVarP(&rType, "runtime", "r", "", "runtime")
	rootCmd.PersistentFlags().StringSliceVarP(&kongImages, "gateway-images", "g", defaultKongImageList, "kong images")
	rootCmd.PersistentFlags().StringSliceVarP(&meshImages, "mesh-images", "m", defaultMeshImageList, "mesh images")
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
	log.Debug("trying to guess runtime...")
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
		return err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return err
	}

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
		_, b, err := cli.ContainerInspectWithRaw(ctx, c.ID, false)
		if err != nil {
			return err
		}

		prettyJSON, err := formatJSON(b)
		if err != nil {
			return err
		}

		sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(c.Image, ":", "/"), "/", "-")
		sanitizedContainerName := strings.ReplaceAll(c.Names[0], "/", "")
		inspectFilename := fmt.Sprintf("%s-%s.json", sanitizedContainerName, sanitizedImageName)
		inspectFile, err := os.Create(inspectFilename)
		if err != nil {
			return err
		}

		log.Debugf("writing docker inspect data for %s", sanitizedContainerName)
		_, err = io.Copy(inspectFile, bytes.NewReader(prettyJSON))
		if err != nil {
			return err
		}

		err = inspectFile.Close()
		if err != nil {
			return err
		}
		filesToZip = append(filesToZip, inspectFilename)

		options := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
		logs, err := cli.ContainerLogs(ctx, c.ID, options)
		if err != nil {
			return err
		}

		logsFilename := fmt.Sprintf("%s-%s.log", sanitizedContainerName, sanitizedImageName)
		logFile, err := os.Create(logsFilename)
		if err != nil {
			return err
		}

		log.Debugf("writing docker logs data for %s", sanitizedContainerName)
		_, err = io.Copy(logFile, logs)
		if err != nil {
			return err
		}

		err = logFile.Close()
		if err != nil {
			return err
		}

		filesToZip = append(filesToZip, logsFilename)
	}

	log.Debugf("writing tar.gz output")
	err = writeFiles(filesToZip)
	if err != nil {
		return err
	}

	return nil
}

func getAPIDumps(endpoint, apiKey string) (map[string]string, error) {
	// https://github.com/Kong/deck/blob/main/dump/dump.go#L244
	return map[string]string{"": ""}, nil
}

func runKubernetes() error {
	ctx := context.Background()
	var kongK8sPods []corev1.Pod
	var filesToZip []string

	kubeClient, err := createClient()
	if err != nil {
		return err
	}
	pl, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{})
	for _, p := range pl.Items {
		for _, c := range p.Spec.Containers {
			for _, i := range append(kongImages, meshImages...) {
				if strings.Contains(c.Image, i) {
					kongK8sPods = append(kongK8sPods, p)
				}
			}
		}
	}
	logFilenames, err := writePodDetails(ctx, kubeClient, kongK8sPods)
	if err != nil {
		return err
	}
	filesToZip = append(filesToZip, logFilenames...)

	err = writeFiles(filesToZip)
	if err != nil {
		return err
	}

	return nil
}

func runVM() error {

	return nil
}

func createClient() (kubernetes.Interface, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

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
			return logFilenames, err
		}
		for _, container := range append(p.Spec.InitContainers, p.Spec.Containers...) {
			podLogOpts := corev1.PodLogOptions{Container: container.Name}
			// podLogOpts.TailLines = &[]int64{int64(100)}[0]
			podLogs, err := clientSet.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts).Stream(ctx)
			if err != nil {
				return logFilenames, err
			}

			sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(container.Image, ":", "/"), "/", "-")
			logsFilename := fmt.Sprintf("%s-%s.log", pod.Name, sanitizedImageName)

			logFile, err := os.Create(logsFilename)
			if err != nil {
				panic(err)
			}

			_, err = io.Copy(logFile, podLogs)
			if err != nil {
				return logFilenames, err
			}

			err = podLogs.Close()
			if err != nil {
				return logFilenames, err
			}

			err = logFile.Close()
			if err != nil {
				return logFilenames, err
			}

			logFilenames = append(logFilenames, logsFilename)
		}
		podDefFileName := fmt.Sprintf("%s.yaml", p.Name)
		podDefFile, err := os.Create(podDefFileName)
		if err != nil {
			panic(err)
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
		_, err = io.Copy(podDefFile, buf)
		if err != nil {
			return logFilenames, err
		}
		logFilenames = append(logFilenames, podDefFileName)
	}
	return logFilenames, nil
}

func writeFiles(filesToWrite []string) error {
	output, err := os.Create("output.tar.gz")
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
