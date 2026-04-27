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
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
	"github.com/shirou/gopsutil/v4/net"
	log "github.com/sirupsen/logrus"
)

// CollectVM performs log and configuration collection from VM deployments.
func CollectVM(ctx context.Context, cfg *Config) ([]string, error) {
	log.Info("Running in VM mode")

	if cfg.LineLimit == LineLimitDefault {
		log.WithField("lineLimit", LineLimitDefault).Info("Using default line limit value")
	}

	var filesToZip []string

	filesToCopy := [][2]string{
		{"/etc/resolv.conf", VMResolvFile},
		{"/etc/hosts", VMHostsFile},
	}

	prefixDir := cfg.PrefixDir
	if prefixDir != "" {
		log.WithField("prefixDir", prefixDir).Info("Reading environment file")

		d, err := os.ReadFile(prefixDir + "/.kong_env")
		if err != nil {
			log.WithError(err).Error("Error reading config file")
			return nil, err
		}

		configSummary, err := os.Create("vm-kong-env.txt")
		if err != nil {
			log.WithError(err).Error("Error creating vm-kong-env.txt")
			return nil, err
		}

		log.Info("Writing kong environment data")
		if _, err = io.Copy(configSummary, bytes.NewReader(d)); err != nil {
			log.WithError(err).Error("Error writing kong environment data")
			configSummary.Close()
			return nil, err
		}

		if err = configSummary.Close(); err != nil {
			log.WithError(err).Error("Error closing vm-kong-env.txt")
			return nil, err
		}

		filesToZip = append(filesToZip, "vm-kong-env.txt")

		// Collect VM resources in parallel
		type resourceTask struct {
			function     func() (interface{}, error)
			resourceType string
			logFile      string
		}

		tasks := []resourceTask{
			{RetrieveVMMemoryInfo, "memory", VMMemoryLogFile},
			{RetrieveVMCPUInfo, "cpu", VMCPULogFile},
			{RetrieveVMDiskInfo, "disk", VMDiskLogFile},
			{RetrieveProcessInfo, "process", VMProcessLogFile},
			{RetrieveNetworkInfo, "network", VMNetworkLogFile},
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		resourceFiles := make([]string, 0, len(tasks))

		for _, task := range tasks {
			wg.Add(1)
			go func(t resourceTask) {
				defer wg.Done()

				if err := getResourceAndMarshall(t.function, t.resourceType, t.logFile); err != nil {
					log.WithFields(log.Fields{
						"resourceType": t.resourceType,
						"error":        err,
					}).Error("Error retrieving resource info")
				} else {
					mu.Lock()
					resourceFiles = append(resourceFiles, t.logFile)
					mu.Unlock()
				}
			}(task)
		}

		// Wait for all resource collection to complete
		wg.Wait()

		// Add all successfully collected resource files
		filesToZip = append(filesToZip, resourceFiles...)

		for _, v := range filesToCopy {
			if err := copyFiles(v[0], v[1]); err != nil {
				log.WithFields(log.Fields{
					"src":   v[0],
					"dst":   v[1],
					"error": err,
				}).Error("Error copying file")
			} else {
				filesToZip = append(filesToZip, v[1])
			}
		}

		// Config keys that have the paths to log files that need extracting
		configKeys := []string{"admin_access_log", "admin_error_log", "proxy_access_log", "proxy_error_log"}

		for _, v := range configKeys {
			logName := collectAndLimitLog(string(d), v, prefixDir, cfg.LineLimit, cfg.RedactTerms)
			if logName != "" {
				filesToZip = append(filesToZip, logName)
			}
		}
	} else {
		log.Warn("No prefix directory set. The prefix parameter must be set for VM log extraction.")
	}

	return filesToZip, nil
}

// getResourceAndMarshall retrieves resource information and marshals it to a JSON file.
func getResourceAndMarshall(functionName func() (interface{}, error), resourceType string, logFile string) error {
	log.WithFields(log.Fields{
		"resourceType": resourceType,
		"logFile":      logFile,
	}).Debug("Retrieving and marshalling resource")

	resource, err := functionName()
	if err != nil {
		return err
	}

	infoJSON, err := json.Marshal(resource)
	if err != nil {
		return err
	}

	err = os.WriteFile(logFile, infoJSON, 0644)
	if err != nil {
		return err
	}

	return nil
}

// collectAndLimitLog collects logs and limits them to a specific number of lines.
func collectAndLimitLog(envars, configKey, prefixDir string, lineLimit int64, strToRedact []string) string {
	log.WithField("configKey", configKey).Debug("Collecting and limiting log")

	splitEnvars := strings.Split(envars, "\n")

	for _, configLine := range splitEnvars {
		if strings.Contains(configLine, configKey) {
			logPath := getConfigValue(configLine)

			if logPath == "" {
				log.WithField("configKey", configKey).Warn("Empty log path found, skipping")
				continue
			}

			var logLines []string

			if logPath[:4] == "logs" {
				fullLogPath := prefixDir + "/" + logPath
				log.WithFields(log.Fields{
					"prefix":   prefixDir,
					"logPath":  logPath,
					"fullPath": fullLogPath,
				}).Debug("Using prefix for log path")
				logPath = fullLogPath
			}

			// Get file length in bytes
			logLength := getFileLength(logPath)
			if logLength <= 0 {
				log.WithField("logPath", logPath).Info("Log file has no length, continuing...")
				continue
			}

			log.WithFields(log.Fields{
				"path":   logPath,
				"length": logLength,
			}).Debug("Log file information")

			logFile, err := os.Open(logPath)
			if err != nil {
				log.WithFields(log.Fields{
					"logPath": logPath,
					"error":   err,
				}).Error("Error opening log")
				continue
			}

			defer logFile.Close()

			// Use buffered reading for better performance
			const bufferSize = 64 * 1024 // 64KB buffer
			buffer := make([]byte, bufferSize)
			var singleLineBytes []byte
			linesProcessed := int64(0)
			bytesProcessed := int64(0)
			success := false

			// Read backwards in chunks
			for bytesProcessed < logLength && linesProcessed < lineLimit {
				// Calculate how much to read
				chunkSize := int64(bufferSize)
				readPos := logLength - bytesProcessed - chunkSize
				if readPos < 0 {
					chunkSize += readPos
					readPos = 0
				}

				// Read a chunk
				n, err := logFile.ReadAt(buffer[:chunkSize], readPos)
				if err != nil && err != io.EOF {
					log.WithFields(log.Fields{
						"logPath": logPath,
						"error":   err,
					}).Error("Unable to read from log file")
					break
				}

				// Process the chunk backwards
				for i := n - 1; i >= 0 && linesProcessed < lineLimit; i-- {
					lastReadByte := buffer[i]
					bytesProcessed++

					// Check for \n byte
					if lastReadByte == 10 {
						// Reverse the line since we're reading backwards
						for j, k := 0, len(singleLineBytes)-1; j < k; j, k = j+1, k-1 {
							singleLineBytes[j], singleLineBytes[k] = singleLineBytes[k], singleLineBytes[j]
						}

						logLines = append(logLines, string(singleLineBytes))
						singleLineBytes = singleLineBytes[:0] // Reuse slice
						linesProcessed++
						success = true
					} else {
						singleLineBytes = append(singleLineBytes, lastReadByte)
					}
				}

				if bytesProcessed >= logLength || linesProcessed >= lineLimit {
					break
				}
			}

			if success {
				// Flip the lines as they are read backwards
				for i, j := 0, len(logLines)-1; i < j; i, j = i+1, j-1 {
					logLines[i], logLines[j] = logLines[j], logLines[i]
				}

				sanitizedLogLines := logLines
				if len(strToRedact) > 0 {
					for i, v := range logLines {
						sanitizedLogLines[i] = AnalyseLogLineForRedaction(v, strToRedact)
					}
				}

				concatLogs := strings.Join(sanitizedLogLines, "\n")
				if len(concatLogs) > 0 {
					logName, err := createAndWriteLogFile(configKey, concatLogs)
					if err != nil {
						log.WithFields(log.Fields{
							"configKey": configKey,
							"error":     err,
						}).Error("Error creating or writing log file")
					} else {
						log.WithFields(log.Fields{
							"configKey": configKey,
							"logName":   logName,
						}).Info("Log file successfully created")
						return logName
					}
				} else {
					log.WithField("configKey", configKey).Info("Skipping creation of logs as the log either does not exist or has no length")
				}

				log.WithFields(log.Fields{
					"configKey":  configKey,
					"linesCount": len(sanitizedLogLines),
				}).Info("Finished reading log")
			}

			logFile.Close()
		}
	}

	return ""
}

// getConfigValue extracts the value from a configuration entry.
func getConfigValue(entry string) string {
	aEntry := strings.Split(entry, "=")
	if len(aEntry) < 2 {
		return ""
	}
	return strings.Trim(aEntry[1], " ")
}

// getFileLength returns the length of a file in bytes.
func getFileLength(logPath string) int64 {
	log.WithField("path", logPath).Debug("Getting log file length")
	size := int64(0)

	fileInfo, err := os.Stat(logPath)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  logPath,
			"error": err,
		}).Error("Error reading file info")
		return 0
	}

	size = fileInfo.Size()
	log.WithFields(log.Fields{
		"path": logPath,
		"size": size,
	}).Debug("File size determined")

	return size
}

// copyFiles copies a file from source to destination.
func copyFiles(srcFile string, dstFile string) error {
	log.WithFields(log.Fields{
		"src": srcFile,
		"dst": dstFile,
	}).Debug("Copying file")

	sourceFile, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}

	return nil
}

// roundToTwoDecimals rounds a float64 to two decimal places.
func roundToTwoDecimals(num float64) float64 {
	return math.Round(num*100) / 100
}

// RetrieveNetworkInfo retrieves network connection information.
func RetrieveNetworkInfo() (interface{}, error) {
	log.Debug("Retrieving network information")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pre-allocate with reasonable capacity
	netStats := make([]NetworkInfo, 0, 100)
	conn, err := net.ConnectionsWithContext(ctx, "all")

	if err != nil {
		log.WithError(err).Error("Failed to retrieve network connections")
		return NetworkInfo{}, err
	}

	for _, v := range conn {
		netStats = append(netStats, NetworkInfo{
			Fd:     v.Fd,
			Family: v.Family,
			Type:   v.Type,
			Laddr:  v.Laddr.IP,
			Raddr:  v.Raddr.IP,
			Status: v.Status,
			Pid:    v.Pid,
			Uids:   v.Uids,
		})
	}

	return netStats, nil
}

// RetrieveProcessInfo retrieves information about running processes.
func RetrieveProcessInfo() (interface{}, error) {
	log.Debug("Retrieving process information")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pre-allocate with reasonable capacity
	ps := make([]ProcessInfo, 0, 100)
	processes, err := process.ProcessesWithContext(ctx)

	if err != nil {
		log.WithError(err).Error("Failed to retrieve processes")
		return ProcessInfo{}, err
	}

	for _, p := range processes {
		name, err := p.NameWithContext(ctx)
		if err != nil {
			log.WithFields(log.Fields{
				"pid":   p.Pid,
				"error": err,
			}).Debug("Failed to get process name")
			continue
		}

		pid := p.Pid
		cpuPercent, err := p.CPUPercentWithContext(ctx)
		if err != nil {
			log.WithFields(log.Fields{
				"pid":   p.Pid,
				"error": err,
			}).Debug("Failed to get process CPU usage")
			continue
		}

		memInfo, err := p.MemoryInfoWithContext(ctx)
		if err != nil {
			log.WithFields(log.Fields{
				"pid":   p.Pid,
				"error": err,
			}).Debug("Failed to get process memory info")
			continue
		}

		cmdLine, err := p.CmdlineWithContext(ctx)
		if err != nil {
			log.WithFields(log.Fields{
				"pid":   p.Pid,
				"error": err,
			}).Debug("Failed to get process command line")
			continue
		}

		ps = append(ps, ProcessInfo{
			PID:        pid,
			Name:       name,
			CPUPercent: fmt.Sprintf("%.2f", cpuPercent),
			MemPercent: memInfo.RSS,
			CmdLine:    cmdLine,
		})
	}
	return ps, nil
}

// RetrieveVMDiskInfo retrieves VM disk usage information.
func RetrieveVMDiskInfo() (interface{}, error) {
	log.Debug("Retrieving VM disk information")
	var bytesToGB uint64 = 1024 * 1024 * 1024
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	diskinfo, err := disk.UsageWithContext(ctx, "/")
	if err != nil {
		log.WithError(err).Error("Failed to retrieve disk usage")
		return DiskInfo{}, err
	}

	return DiskInfo{
		Total:       diskinfo.Total / bytesToGB,
		Free:        diskinfo.Free / bytesToGB,
		Used:        diskinfo.Used / bytesToGB,
		UsedPercent: diskinfo.UsedPercent,
	}, nil
}

// RetrieveVMCPUInfo retrieves VM CPU information.
func RetrieveVMCPUInfo() (interface{}, error) {
	log.Debug("Retrieving VM CPU information")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cpuinfo, err := cpu.InfoWithContext(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve CPU information")
		return CPUInfo{}, err
	}

	if len(cpuinfo) == 0 {
		log.Warn("No CPU info retrieved")
		return CPUInfo{}, fmt.Errorf("no CPU information available")
	}

	return CPUInfo{
		CPU:   len(cpuinfo),
		Cores: cpuinfo[0].Cores,
	}, nil
}

// RetrieveVMMemoryInfo retrieves VM memory information.
func RetrieveVMMemoryInfo() (interface{}, error) {
	log.Debug("Retrieving VM memory information")
	bytesToGB := 1024.0 * 1024.0 * 1024.0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	memInfo, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve virtual memory info")
		return MemoryInfo{}, err
	}

	swapMem, err := mem.SwapMemory()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve swap memory info")
		return MemoryInfo{}, err
	}

	return MemoryInfo{
		PhysicalTotal:     roundToTwoDecimals(float64(memInfo.Total) / bytesToGB),
		PhysicalAvailable: roundToTwoDecimals(float64(memInfo.Available) / bytesToGB),
		SwapTotal:         roundToTwoDecimals(float64(swapMem.Total) / bytesToGB),
		SwapFree:          roundToTwoDecimals(float64(swapMem.Free) / bytesToGB),
	}, nil
}
