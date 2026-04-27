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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DetectRuntime attempts to detect the Kong deployment runtime.
// It checks for Docker, Kubernetes, and VM deployments in order.
// Returns the detected runtime string or an error if none could be detected.
func DetectRuntime(kongImages []string, prefixDir string) (string, error) {
	log.Info("Trying to guess runtime...")
	var errList []string

	// Try Docker first
	runtime, err := tryDetectDocker(kongImages)
	if err != nil {
		errList = append(errList, err.Error())
	} else if runtime != "" {
		return runtime, nil
	}

	// Try Kubernetes
	runtime, err = tryDetectKubernetes(kongImages)
	if err != nil {
		errList = append(errList, err.Error())
	} else if runtime != "" {
		return runtime, nil
	}

	// Try VM
	runtime, detectedPrefixDir, err := tryDetectVM(prefixDir)
	if err != nil {
		errList = append(errList, err.Error())
	} else if runtime != "" {
		// Note: We can't modify the prefixDir parameter here, caller should handle this
		_ = detectedPrefixDir
		return runtime, nil
	}

	return "", fmt.Errorf("could not detect runtime:\n%s", strings.Join(errList, "\n"))
}

// tryDetectDocker checks if Docker is available and has Kong containers running.
func tryDetectDocker(kongImages []string) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}

	_, err = cli.ServerVersion(ctx)
	if err != nil {
		return "", err
	}

	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return "", err
	}

	var kongContainers []types.Container
	for _, c := range containers {
		for _, i := range kongImages {
			if strings.Contains(c.Image, i) {
				kongContainers = append(kongContainers, c)
			}
		}
	}

	if len(kongContainers) > 0 {
		log.Info("Docker runtime detected")
		return RuntimeDocker, nil
	}

	return "", nil
}

// tryDetectKubernetes checks if Kubernetes is available and has Kong pods running.
func tryDetectKubernetes(kongImages []string) (string, error) {
	kubeClient, _, err := createK8sClient()
	if err != nil {
		return "", err
	}

	pl, err := kubeClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return "", err
	}

	var kongK8sPods []string
	for _, p := range pl.Items {
		for _, c := range p.Spec.Containers {
			for _, i := range kongImages {
				if strings.Contains(c.Image, i) {
					kongK8sPods = append(kongK8sPods, p.Name)
				}
			}
		}
	}

	if len(kongK8sPods) > 0 {
		log.Info("Kubernetes runtime detected")
		return RuntimeKubernetes, nil
	}

	return "", nil
}

// tryDetectVM checks if this is a VM deployment by looking for Kong prefix directory.
// Returns the runtime, the detected prefix directory, and any error.
func tryDetectVM(prefixDir string) (string, string, error) {
	// Check default location first
	if _, err := os.Stat("/usr/local/kong/.kong_env"); err == nil {
		log.Info("VM runtime detected")
		return RuntimeVM, "/usr/local/kong", nil
	}

	// Try alternate prefix directory
	if _, err := os.Stat("/KONG_PREFIX/.kong_env"); err == nil {
		log.Info("VM runtime detected with alternate prefix directory")
		return RuntimeVM, "/KONG_PREFIX", nil
	}

	// Try the provided prefix directory
	if prefixDir != "" && prefixDir != "/usr/local/kong" {
		envPath := prefixDir + "/.kong_env"
		if _, err := os.Stat(envPath); err == nil {
			log.Info("VM runtime detected with custom prefix directory")
			return RuntimeVM, prefixDir, nil
		}
	}

	return "", "", fmt.Errorf("VM runtime not detected: no .kong_env file found")
}

// createK8sClient creates a Kubernetes client from the default kubeconfig.
func createK8sClient() (kubernetes.Interface, *rest.Config, error) {
	log.Debug("Creating Kubernetes client")
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)

	clientConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("error finding Kubernetes API server config in --kubeconfig, $KUBECONFIG, or in-cluster configuration: %w", err)
	}

	clientSet, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a client: %w", err)
	}

	return clientSet, clientConfig, nil
}
