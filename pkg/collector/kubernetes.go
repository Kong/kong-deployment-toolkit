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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// CollectKubernetes performs log and configuration collection from Kubernetes pods.
func CollectKubernetes(ctx context.Context, cfg *Config) ([]string, error) {
	filesToCopy := []string{
		"/etc/resolv.conf",
		"/etc/hosts",
		"/etc/os-release",
	}

	commandsToRun := []NamedCommand{
		{Cmd: []string{"top", "-b", "-n", "1"}, Name: "top"},
		{Cmd: []string{"ls", "-lart", "/usr/local/share/lua/5.1/kong/templates"}, Name: "templates"},
		{Cmd: []string{"sh", "-c", "ulimit", "-n"}, Name: "ulimit"},
		{Cmd: []string{"uname", "-a"}, Name: "uname"},
		{Cmd: []string{"ps", "aux"}, Name: "ps"},
		{Cmd: []string{"df", "-h"}, Name: "df"},
		{Cmd: []string{"free", "-h"}, Name: "free"},
	}

	log.Info("Running Kubernetes collection")

	if cfg.Namespace == "" {
		return nil, fmt.Errorf("namespace is required for Kubernetes collection; use --namespace to specify")
	}

	// Pre-allocate with reasonable capacity
	kongK8sPods := make([]corev1.Pod, 0, 20)
	filesToZip := make([]string, 0, 50)

	kubeClient, clientConfig, err := createK8sClient()
	if err != nil {
		log.WithError(err).Error("Unable to create k8s client")
		return nil, err
	}

	pl, err := kubeClient.CoreV1().Pods(cfg.Namespace).List(ctx, v1.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to list pods")
		return nil, err
	}

	targetPods := cfg.TargetPods

	// To keep track of whether a particular pod has been added already.
	foundPod := make(map[string]bool)

	for _, p := range pl.Items {
		if len(targetPods) > 0 {
			for _, podName := range targetPods {
				if strings.ToLower(podName) == strings.ToLower(p.Name) {
					for _, c := range p.Spec.Containers {
						for _, i := range cfg.TargetImages {
							if strings.Contains(c.Image, i) {
								if !foundPod[p.Name] {
									log.WithFields(log.Fields{
										"pod":            p.Name,
										"containerCount": len(p.Spec.Containers),
									}).Info("Found target pod")
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
				for _, i := range cfg.TargetImages {
					if strings.Contains(c.Image, i) {
						if !foundPod[p.Name] {
							log.WithFields(log.Fields{
								"pod":            p.Name,
								"containerCount": len(p.Spec.Containers),
							}).Info("Found Kong pod")
							kongK8sPods = append(kongK8sPods, p)
							foundPod[p.Name] = true
						}
					}
				}
			}
		}
	}

	if len(kongK8sPods) > 0 {
		log.WithField("podCount", len(kongK8sPods)).Info("Processing Kubernetes pods")

		logFilenames, err := writePodDetails(ctx, kubeClient, kongK8sPods, cfg)
		if err != nil {
			log.WithError(err).Error("Error writing pod details")
		} else {
			filesToZip = append(filesToZip, logFilenames...)
		}

		// Process pods in parallel with controlled concurrency
		var wg sync.WaitGroup
		var mu sync.Mutex
		// Limit concurrent pod processing to 10 to avoid overwhelming the API server
		semaphore := make(chan struct{}, 10)

		for _, pod := range kongK8sPods {
			wg.Add(1)
			go func(p corev1.Pod) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire semaphore
				defer func() { <-semaphore }() // Release semaphore

				log.WithFields(log.Fields{
					"pod":       p.Name,
					"namespace": p.Namespace,
				}).Info("Processing pod")

				var podFiles []string

				for _, container := range p.Spec.Containers {
					relevantImage := false
					for _, i := range cfg.TargetImages {
						if strings.Contains(container.Image, i) {
							relevantImage = true
							break
						}
					}

					if !relevantImage {
						continue
					}

					log.WithField("container", container.Name).Info("Processing container")

					for _, file := range filesToCopy {
						namedCmd := NamedCommand{
							Cmd:  []string{"cat", file},
							Name: file,
						}

						filename, err := RunCommandInPod(ctx, kubeClient, clientConfig, p.Namespace, p.Name, container.Name, namedCmd)
						if err != nil {
							log.WithFields(log.Fields{
								"pod":       p.Name,
								"container": container.Name,
								"file":      file,
								"error":     err,
							}).Error("Error copying file from pod")
						} else if filename != "" {
							log.WithFields(log.Fields{
								"pod":      p.Name,
								"file":     file,
								"filename": filename,
							}).Debug("Copied file from pod")
							podFiles = append(podFiles, filename)
						}
					}

					for _, namedCmd := range commandsToRun {
						filename, err := RunCommandInPod(ctx, kubeClient, clientConfig, p.Namespace, p.Name, container.Name, namedCmd)
						if err != nil {
							log.WithFields(log.Fields{
								"pod":       p.Name,
								"container": container.Name,
								"command":   strings.Join(namedCmd.Cmd, " "),
								"error":     err,
							}).Error("Error running command in pod")
						} else if filename != "" {
							log.WithFields(log.Fields{
								"pod":      p.Name,
								"command":  strings.Join(namedCmd.Cmd, " "),
								"filename": filename,
							}).Debug("Command executed in pod")
							podFiles = append(podFiles, filename)
						}
					}
				}

				// Add collected files to the shared filesToZip slice with mutex protection
				if len(podFiles) > 0 {
					mu.Lock()
					filesToZip = append(filesToZip, podFiles...)
					mu.Unlock()
				}
			}(pod)
		}

		// Wait for all pods to be processed
		wg.Wait()
	} else {
		log.Warn("No pods with the appropriate container images found in cluster")
	}

	return filesToZip, nil
}

// writePodDetails writes pod logs and definitions to files.
func writePodDetails(ctx context.Context, clientSet kubernetes.Interface, podList []corev1.Pod, cfg *Config) ([]string, error) {
	// Pre-allocate with estimated capacity (2 files per pod: logs + yaml)
	logFilenames := make([]string, 0, len(podList)*2)

	for _, pod := range podList {
		p, err := clientSet.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			log.WithFields(log.Fields{
				"pod":       pod.Name,
				"namespace": pod.Namespace,
				"error":     err,
			}).Error("Error getting pod details")
			continue
		}

		log.WithFields(log.Fields{
			"pod":       p.Name,
			"namespace": p.Namespace,
		}).Info("Processing pod details")

		for _, container := range p.Spec.Containers {
			relevantImage := false
			for _, i := range cfg.TargetImages {
				if strings.Contains(container.Image, i) {
					relevantImage = true
					break
				}
			}

			if !relevantImage {
				continue
			}

			log.WithField("container", container.Name).Info("Processing container logs")

			logsSinceSeconds := cfg.K8sLogsSinceSeconds

			lineLimit := cfg.LineLimit
			podLogOpts := corev1.PodLogOptions{Container: container.Name}
			if logsSinceSeconds > 0 {
				podLogOpts.SinceSeconds = &logsSinceSeconds
				log.WithField("sinceSeconds", logsSinceSeconds).Debug("Using time-based log retrieval")
			} else {
				podLogOpts.TailLines = &lineLimit
				log.WithField("tailLines", lineLimit).Debug("Using line-based log retrieval")
			}

			podLogs, err := clientSet.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts).Stream(ctx)
			if err != nil {
				log.WithFields(log.Fields{
					"pod":       pod.Name,
					"container": container.Name,
					"error":     err,
				}).Error("Error retrieving pod logs")
				continue
			}

			sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(container.Image, ":", "/"), "/", "-")
			logsFilename := fmt.Sprintf("%s-%s.log", pod.Name, sanitizedImageName)

			logFile, err := os.Create(logsFilename)
			if err != nil {
				log.WithFields(log.Fields{
					"filename": logsFilename,
					"error":    err,
				}).Error("Error creating log file")
				podLogs.Close()
				continue
			}

			if len(cfg.RedactTerms) > 0 {
				buf := bufio.NewScanner(podLogs)
				for buf.Scan() {
					logBytes := buf.Bytes()
					sanitizedLogLine := AnalyseLogLineForRedaction(string(logBytes)+"\n", cfg.RedactTerms)
					if _, err := io.Copy(logFile, strings.NewReader(sanitizedLogLine)); err != nil {
						log.WithError(err).Error("Unable to write container logs")
						break
					}
				}
			} else {
				if _, err := io.Copy(logFile, podLogs); err != nil {
					log.WithError(err).Error("Error copying pod logs to file")
					logFile.Close()
					podLogs.Close()
					continue
				}
			}

			podLogs.Close()
			logFile.Close()
			logFilenames = append(logFilenames, logsFilename)
		}

		podDefFileName := fmt.Sprintf("%s.yaml", p.Name)
		podDefFile, err := os.Create(podDefFileName)
		if err != nil {
			log.WithFields(log.Fields{
				"filename": podDefFileName,
				"error":    err,
			}).Error("Error creating pod definition file")
			continue
		}

		buf := bytes.NewBufferString("")
		pod.TypeMeta = metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		}

		scheme := runtime.NewScheme()
		serializer := kjson.NewSerializerWithOptions(
			kjson.DefaultMetaFactory,
			scheme,
			scheme,
			kjson.SerializerOptions{
				Pretty: true,
				Yaml:   true,
				Strict: true,
			},
		)

		err = serializer.Encode(&pod, buf)
		if err != nil {
			log.WithError(err).Error("Error encoding pod definition")
			podDefFile.Close()
			continue
		}

		_, err = io.Copy(podDefFile, buf)
		if err != nil {
			log.WithError(err).Error("Error writing pod definition")
			podDefFile.Close()
			continue
		}

		podDefFile.Close()
		logFilenames = append(logFilenames, podDefFileName)
	}

	return logFilenames, nil
}

// RunCommandInPod executes a command inside a Kubernetes pod container.
func RunCommandInPod(
	ctx context.Context,
	clientset kubernetes.Interface,
	config *rest.Config,
	namespace string,
	pod string,
	container string,
	namedCmd NamedCommand) (string, error) {

	log.WithFields(log.Fields{
		"namespace": namespace,
		"pod":       pod,
		"container": container,
		"command":   strings.Join(namedCmd.Cmd, " "),
	}).Debug("Running command in pod")

	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		Param("container", container).
		Param("stdin", "false").
		Param("stdout", "true").
		Param("stderr", "true")

	for _, c := range namedCmd.Cmd {
		req.Param("command", c)
	}

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		log.WithFields(log.Fields{
			"namespace": namespace,
			"pod":       pod,
			"container": container,
			"error":     err,
		}).Error("Error creating executor")
		return "", err
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		log.WithFields(log.Fields{
			"namespace": namespace,
			"pod":       pod,
			"container": container,
			"error":     err,
			"stderr":    stderr.String(),
		}).Warning("Error streaming command output")
		return "", err
	}

	sanitizedName := strings.ReplaceAll(namedCmd.Name, "/", "-")
	dstFile := fmt.Sprintf("%s-%s.log", container, sanitizedName)

	err = WriteOutputToFile(dstFile, stdout.Bytes())
	if err != nil {
		log.WithFields(log.Fields{
			"filename": dstFile,
			"error":    err,
		}).Error("Error writing file")
		return "", err
	}

	return dstFile, nil
}

// createAndWriteLogFile creates a log file with hostname prefix and timestamp.
func createAndWriteLogFile(initialLogName string, contents string) (string, error) {
	hostname, _ := os.Hostname()
	logName := fmt.Sprintf(hostname+"_"+initialLogName+"-%s.log", time.Now().Format("2006-01-02-15-04-05"))

	logFile, err := os.Create(logName)
	if err != nil {
		log.WithFields(log.Fields{
			"initialLogName": initialLogName,
			"error":          err,
		}).Error("Cannot create log file")
		return "", err
	}

	defer logFile.Close()

	if _, err = io.Copy(logFile, strings.NewReader(contents)); err != nil {
		log.WithFields(log.Fields{
			"initialLogName": initialLogName,
			"error":          err,
		}).Error("Unable to write contents to log file")
		return "", err
	}

	return logName, nil
}
