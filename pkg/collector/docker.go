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
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	log "github.com/sirupsen/logrus"
)

// CollectDocker performs log and configuration collection from Docker containers.
// Intermediate files are written under workDir rather than the current working directory.
func CollectDocker(ctx context.Context, cfg *Config, workDir string) ([]string, error) {
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

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.WithError(err).Error("Unable to create docker api client")
		return nil, err
	}

	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Unable to get container list from docker api")
		return nil, err
	}

	log.WithField("count", len(containers)).Info("Found containers running")

	// Pre-allocate with reasonable capacity
	kongContainers := make([]types.Container, 0, 10)

	for _, c := range containers {
		for _, i := range cfg.TargetImages {
			if strings.Contains(c.Image, i) {
				kongContainers = append(kongContainers, c)
			}
		}
	}

	log.WithField("count", len(kongContainers)).Info("Found Kong containers")

	// Pre-allocate with estimated capacity (files per container * container count)
	filesToZip := make([]string, 0, len(kongContainers)*5)

	for _, c := range kongContainers {
		log.WithField("containerID", c.ID).Info("Inspecting container")

		copiedFiles, err := CopyFilesFromContainers(ctx, cli, c.ID, filesToCopy, workDir)
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": c.ID,
				"error":       err,
			}).Error("Error copying files from container")
		}

		executedFiles, err := RunCommandsInContainer(ctx, cli, c.ID, commandsToRun, workDir)
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": c.ID,
				"error":       err,
			}).Error("Error running commands in container")
		}

		log.WithField("count", len(copiedFiles)).Debug("Files copied from container")
		filesToZip = append(filesToZip, copiedFiles...)
		filesToZip = append(filesToZip, executedFiles...)

		_, b, err := cli.ContainerInspectWithRaw(ctx, c.ID, false)
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": c.ID,
				"error":       err,
			}).Error("Unable to inspect container")
			continue
		}

		prettyJSON, err := formatJSON(b)
		if err != nil {
			log.WithError(err).Error("Unable to format JSON")
			continue
		}

		sanitizedImageName := strings.ReplaceAll(strings.ReplaceAll(c.Image, ":", "/"), "/", "-")
		sanitizedContainerName := strings.ReplaceAll(c.Names[0], "/", "")
		inspectFilename := filepath.Join(workDir, fmt.Sprintf("%s-%s.json", sanitizedContainerName, sanitizedImageName))
		inspectFile, err := os.Create(inspectFilename)
		if err != nil {
			log.WithFields(log.Fields{
				"filename": inspectFilename,
				"error":    err,
			}).Error("Unable to create inspection file")
			continue
		}

		log.WithFields(log.Fields{
			"container": sanitizedContainerName,
			"filename":  inspectFilename,
		}).Info("Writing docker inspect data")

		_, err = io.Copy(inspectFile, bytes.NewReader(prettyJSON))
		if err != nil {
			log.WithError(err).Error("Unable to write inspect file")
			inspectFile.Close()
			continue
		}

		err = inspectFile.Close()
		if err != nil {
			log.WithError(err).Error("Unable to close inspect file")
			continue
		}

		filesToZip = append(filesToZip, inspectFilename)

		logsFilename := filepath.Join(workDir, fmt.Sprintf("%s-%s.log", sanitizedContainerName, sanitizedImageName))
		logFile, err := os.Create(logsFilename)
		if err != nil {
			log.WithFields(log.Fields{
				"filename": logsFilename,
				"error":    err,
			}).Error("Unable to create container log file")
			continue
		}

		logsSinceDocker := cfg.DockerLogsSince

		options := container.LogsOptions{}

		if logsSinceDocker != "" {
			options = container.LogsOptions{ShowStdout: true, ShowStderr: true, Since: logsSinceDocker, Details: false}
			log.WithField("since", logsSinceDocker).Debug("Using time-based log retrieval")
		} else {
			strLineLimit := strconv.Itoa(int(cfg.LineLimit))
			options = container.LogsOptions{ShowStdout: true, ShowStderr: true, Tail: strLineLimit, Details: false}
			log.WithField("lineLimit", cfg.LineLimit).Debug("Using line-based log retrieval")
		}

		logs, err := cli.ContainerLogs(ctx, c.ID, options)
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": c.ID,
				"error":       err,
			}).Error("Unable to retrieve container logs")
			logFile.Close()
			continue
		}

		log.WithFields(log.Fields{
			"container": sanitizedContainerName,
			"filename":  logsFilename,
		}).Info("Writing docker logs data")

		if len(cfg.RedactTerms) > 0 {
			var demuxed bytes.Buffer
			if _, err := stdcopy.StdCopy(&demuxed, &demuxed, logs); err != nil {
				log.WithError(err).Error("Unable to demultiplex container logs")
			}

			scanner := bufio.NewScanner(&demuxed)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				redactedLine := AnalyseLogLineForRedaction(scanner.Text()+"\n", cfg.RedactTerms)
				if _, err := io.WriteString(logFile, redactedLine); err != nil {
					log.WithError(err).Error("Unable to write container logs")
					break
				}
			}
		} else if _, err := stdcopy.StdCopy(logFile, logFile, logs); err != nil {
			log.WithError(err).Error("Unable to demultiplex container logs")
		}

		logs.Close()

		if err := logFile.Close(); err != nil {
			log.WithError(err).Error("Unable to close container logs file")
			continue
		}

		filesToZip = append(filesToZip, logsFilename)
	}

	return filesToZip, nil
}

// AnalyseLogLineForRedaction redacts specified terms from a log line.
func AnalyseLogLineForRedaction(line string, strToRedact []string) string {
	returnLine := strings.ToLower(line)

	for _, v := range strToRedact {
		if strings.Contains(returnLine, strings.ToLower(v)) {
			returnLine = strings.ReplaceAll(returnLine, strings.ToLower(v), "<REDACTED>")
		}
	}

	return returnLine
}

// RunCommandsInContainer executes commands inside a Docker container and saves output to files under workDir.
func RunCommandsInContainer(ctx context.Context, cli *client.Client, containerID string, commands []NamedCommand, workDir string) ([]string, error) {
	// Pre-allocate with the number of commands
	filesToWrite := make([]string, 0, len(commands))

	for _, nc := range commands {
		log.WithFields(log.Fields{
			"containerID": containerID,
			"command":     strings.Join(nc.Cmd, " "),
		}).Debug("Running command in container")

		config := container.ExecOptions{
			Cmd:          nc.Cmd,
			Tty:          false,
			AttachStderr: false,
			AttachStdout: true,
			AttachStdin:  false,
			Detach:       true,
		}

		execID, err := cli.ContainerExecCreate(ctx, containerID, config)
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": containerID,
				"command":     strings.Join(nc.Cmd, " "),
				"error":       err,
			}).Error("Error creating exec")
			continue
		}

		resp, err := cli.ContainerExecAttach(ctx, execID.ID, container.ExecStartOptions{})
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": containerID,
				"execID":      execID.ID,
				"error":       err,
			}).Error("Error attaching to exec")
			continue
		}

		output, err := decodeDockerMultiplexedStream(resp.Reader)
		if err != nil {
			log.WithError(err).Error("Error decoding multiplexed stream")
			resp.Close()
			continue
		}

		resp.Close()

		outputFilename := filepath.Join(workDir, nc.Name)
		err = WriteOutputToFile(outputFilename, output)
		if err != nil {
			log.WithFields(log.Fields{
				"filename": outputFilename,
				"error":    err,
			}).Error("Error writing output to file")
			continue
		}

		filesToWrite = append(filesToWrite, outputFilename)
	}

	return filesToWrite, nil
}

// decodeDockerMultiplexedStream decodes the Docker multiplexed stream format,
// combining stdout and stderr into a single buffer in stream order.
func decodeDockerMultiplexedStream(reader io.Reader) ([]byte, error) {
	var output bytes.Buffer
	if _, err := stdcopy.StdCopy(&output, &output, reader); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

// CopyFilesFromContainers copies files from a Docker container into workDir on the local filesystem.
func CopyFilesFromContainers(ctx context.Context, cli *client.Client, containerID string, files []string, workDir string) ([]string, error) {
	log.WithFields(log.Fields{
		"containerID": containerID,
		"fileCount":   len(files),
	}).Debug("Copying files from container")

	// Pre-allocate with the number of files
	filesToWrite := make([]string, 0, len(files))

	for _, file := range files {
		log.WithFields(log.Fields{
			"containerID": containerID,
			"file":        file,
		}).Debug("Copying file from container")

		reader, _, err := cli.CopyFromContainer(ctx, containerID, file)
		if err != nil {
			log.WithFields(log.Fields{
				"containerID": containerID,
				"file":        file,
				"error":       err,
			}).Error("Error copying file from container")
			continue
		}

		tarReader := tar.NewReader(reader)
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}

			if err != nil {
				log.WithError(err).Error("Error reading tar file")
				break
			}

			// Skip non-regular files (directories, symlinks, etc.)
			if header.Typeflag != tar.TypeReg {
				log.WithFields(log.Fields{
					"filename": header.Name,
					"type":     header.Typeflag,
				}).Debug("Skipping non-regular file")
				continue
			}

			// Warn if file is empty
			if header.Size == 0 {
				log.WithFields(log.Fields{
					"filename": header.Name,
					"size":     header.Size,
				}).Warn("File is empty in container")
			}

			// Use the tar entry's base name only - it originates from the Docker
			// daemon/container and must not be trusted to stay within workDir otherwise.
			outFilename := filepath.Join(workDir, filepath.Base(header.Name))
			outFile, err := os.Create(outFilename)
			if err != nil {
				log.WithFields(log.Fields{
					"filename": outFilename,
					"error":    err,
				}).Error("Error creating file")
				continue
			}

			bytesWritten, err := io.Copy(outFile, tarReader)
			if err != nil {
				log.WithFields(log.Fields{
					"filename": outFilename,
					"error":    err,
				}).Error("Error copying file content")
				outFile.Close()
				continue
			}

			outFile.Close()

			// Only add to list if successfully written
			log.WithFields(log.Fields{
				"filename":     outFilename,
				"bytesWritten": bytesWritten,
			}).Debug("Successfully copied file from container")
			filesToWrite = append(filesToWrite, outFilename)
		}
		reader.Close()
	}

	return filesToWrite, nil
}
