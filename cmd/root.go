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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"os"
	"strings"

	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

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

var rType string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mist",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&rType, "runtime", "", "")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
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

	var kongDockerContainers []types.Container

	for _, container := range containers {
		if strings.Contains(container.Image, "kong") {
			kongDockerContainers = append(kongDockerContainers, container)
		}
	}

	if len(kongDockerContainers) > 0 {
		fmt.Println("Found Docker!")
		return Docker, nil
	}

	var kongK8sPods []string

	kubeClient, err := createClient()
	pl, err := kubeClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})
	for _, p := range pl.Items {
		if strings.Contains(p.Name, "kong") {
			kongK8sPods = append(kongK8sPods, p.Name)
		}
	}

	if len(kongK8sPods) > 0 {
		fmt.Println("Found Kubernetes!")
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
		if strings.Contains(container.Image, "kong") {
			kongContainers = append(kongContainers, container)
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

		inspectFilename := fmt.Sprintf("docker-inspect-%s.log", sanitizedImageName)

		inspectFile, err := os.Create(inspectFilename)
		if err != nil {
			panic(err)
		}
		defer inspectFile.Close()
		_, err = io.Copy(inspectFile, bytes.NewReader(prettyJSON))
		filesToZip = append(filesToZip, inspectFilename)

		options := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
		// Replace this ID with a container that really exists
		logs, err := cli.ContainerLogs(ctx, c.ID, options)
		if err != nil {
			panic(err)
		}

		logsFilename := fmt.Sprintf("docker-logs-%s.log", sanitizedImageName)
		logFile, err := os.Create(logsFilename)
		if err != nil {
			panic(err)
		}

		defer logFile.Close()
		_, err = io.Copy(logFile, logs)
		filesToZip = append(filesToZip, logsFilename)
	}

	writeFiles(filesToZip)

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
		if strings.Contains(p.Name, "kong") {
			kongK8sPods = append(kongK8sPods, p)
		}
	}
	getPodLogs(ctx, kubeClient, kongK8sPods)
	writeFiles(filesToZip)

	return nil
}

func runVM() error {

	return nil
}

// func getPodLogs(pod corev1.Pod) string {
// 	podLogOpts := corev1.PodLogOptions{}
// 	config, err := rest.InClusterConfig()
// 	if err != nil {
// 		return "error in getting config"
// 	}
// 	// creates the clientset
// 	clientset, err := kubernetes.NewForConfig(config)
// 	if err != nil {
// 		return "error in getting access to K8S"
// 	}
// 	req := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)
// 	podLogs, err := req.Stream()
// 	if err != nil {
// 		return "error in opening stream"
// 	}
// 	defer podLogs.Close()

// 	buf := new(bytes.Buffer)
// 	_, err = io.Copy(buf, podLogs)
// 	if err != nil {
// 		return "error in copy information from podLogs to buf"
// 	}
// 	str := buf.String()

// 	return str
// }

func createClient() (kubernetes.Interface, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	clientConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error finding Kubernetes API server config in --kubeconfig, $KUBECONFIG, or in-cluster configuration")
	}

	client, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create a client: %v", err)
	}

	return client, nil
}

func getPodLogs(ctx context.Context, clientSet kubernetes.Interface, podList []corev1.Pod) error {
	for _, pod := range podList {
		p, err := clientSet.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, container := range append(p.Spec.InitContainers, p.Spec.Containers...) {
			podLogOpts := corev1.PodLogOptions{}
			podLogOpts.Follow = true
			podLogOpts.TailLines = &[]int64{int64(100)}[0]
			podLogOpts.Container = container.Name
			podLogs, err := clientSet.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts).Stream(ctx)
			if err != nil {
				return err
			}
			defer podLogs.Close()
			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, podLogs)
			if err != nil {
				return "error in copy information from podLogs to buf"
			}
			str := buf.String()

			logsFilename := fmt.Sprintf("docker-logs-%s.log", sanitizedImageName)
			logFile, err := os.Create(logsFilename)
			if err != nil {
				panic(err)
			}

			defer logFile.Close()
			_, err = io.Copy(logFile, logs)
			filesToZip = append(filesToZip, logsFilename)

		}

	}
	return nil
}

func writeFiles(filesToWrite []string) error {
	output, err := os.Create("output.tar.gz")
	if err != nil {
		log.Fatalln("Error writing archive:", err)
	}
	defer output.Close()

	// Create the archive and write the output to the "out" Writer
	gw := gzip.NewWriter(output)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

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
	defer file.Close()

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
	// If we don't do this the directory strucuture would
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
