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

// Package collector provides functionality for collecting Kong diagnostic data
// from various deployment environments (Docker, Kubernetes, VM).
//
// This package is designed to be used both as a library and by the CLI tool.
// When used as a library, callers should create a Config struct and call
// the Collect function.
//
// Example usage:
//
//	cfg := collector.DefaultConfig()
//	cfg.Runtime = "docker"
//	cfg.KongAddr = "http://localhost:8001"
//
//	result, err := collector.Collect(context.Background(), cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Archive created at: %s\n", result.ArchivePath)
package collector

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"
)

// Collect performs the full data collection process based on the provided configuration.
// It detects or uses the specified runtime, collects relevant data, and creates an archive.
// Returns a Result struct containing the archive path and any warnings encountered.
func Collect(ctx context.Context, cfg *Config) (*Result, error) {
	// Apply defaults for any unset configuration values
	cfg = cfg.WithDefaults()

	// Initialize logging
	initLogging(cfg)

	var filesToZip []string
	var warnings []error

	// Determine runtime
	runtime := cfg.Runtime

	if runtime == "" {
		log.Info("No runtime detected, attempting to guess runtime...")
		detectedRuntime, err := DetectRuntime(cfg.TargetImages, cfg.PrefixDir)
		if err != nil {
			log.WithError(err).Error("Failed to guess runtime")
			return nil, err
		}
		runtime = detectedRuntime
	}

	// Collect based on runtime
	switch runtime {
	case RuntimeDocker:
		log.Info("Using Docker runtime")
		dockerFiles, err := CollectDocker(ctx, cfg)
		if err != nil {
			log.WithError(err).Error("Error with docker runtime collection")
			warnings = append(warnings, err)
		} else {
			filesToZip = append(filesToZip, dockerFiles...)
		}

	case RuntimeKubernetes:
		log.Info("Using Kubernetes runtime")
		k8sFiles, err := CollectKubernetes(ctx, cfg)
		if err != nil {
			log.WithError(err).Error("Error with Kubernetes runtime collection")
			warnings = append(warnings, err)
		} else {
			filesToZip = append(filesToZip, k8sFiles...)
		}

	case RuntimeVM:
		log.Info("Using VM runtime")
		vmFiles, err := CollectVM(ctx, cfg)
		if err != nil {
			log.WithError(err).Error("Error with VM runtime collection")
			warnings = append(warnings, err)
		} else {
			filesToZip = append(filesToZip, vmFiles...)
		}

	default:
		log.WithField("runtime", runtime).Error("Runtime not supported")
	}

	// Handle KDD collection
	if cfg.DisableKDD && cfg.DumpWorkspaceConfigs {
		log.Warn("Cannot create workspaces dumps when KDD collection is disabled")
	}

	if !cfg.DisableKDD {
		log.Info("KDD collection is enabled")

		kddFiles, err := CollectKDD(ctx, cfg)
		if err != nil {
			log.WithError(err).Error("Error with KDD collection")
			warnings = append(warnings, err)
		} else {
			filesToZip = append(filesToZip, kddFiles...)
		}
	}

	// Create the archive
	log.Info("Writing tar.gz output")

	archivePath, err := CreateArchive(filesToZip, cfg.OutputDir)
	if err != nil {
		log.WithError(err).Error("Error writing tar.gz file")
		return nil, err
	}

	return &Result{
		ArchivePath:    archivePath,
		Runtime:        runtime,
		CollectedFiles: filesToZip,
		Warnings:       warnings,
	}, nil
}

// initLogging sets up logrus configuration.
// When cfg.Logger is set (library mode), only redirects logrus output to that writer.
// When cfg.Logger is nil (standalone mode), configures logrus globally with formatting.
func initLogging(cfg *Config) {
	if cfg.Logger != nil {
		log.SetOutput(cfg.Logger)
	} else {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
		log.SetOutput(os.Stdout)
	}

	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

// CollectDocker is a convenience function for collecting Docker data only.
// It does not create an archive - use Collect for full functionality.
func CollectDockerOnly(ctx context.Context, cfg *Config) ([]string, error) {
	cfg = cfg.WithDefaults()
	initLogging(cfg)
	return CollectDocker(ctx, cfg)
}

// CollectKubernetesOnly is a convenience function for collecting Kubernetes data only.
// It does not create an archive - use Collect for full functionality.
func CollectKubernetesOnly(ctx context.Context, cfg *Config) ([]string, error) {
	cfg = cfg.WithDefaults()
	initLogging(cfg)
	return CollectKubernetes(ctx, cfg)
}

// CollectVMOnly is a convenience function for collecting VM data only.
// It does not create an archive - use Collect for full functionality.
func CollectVMOnly(ctx context.Context, cfg *Config) ([]string, error) {
	cfg = cfg.WithDefaults()
	initLogging(cfg)
	return CollectVM(ctx, cfg)
}

// CollectKDDOnly is a convenience function for collecting KDD data only.
// It does not create an archive - use Collect for full functionality.
func CollectKDDOnly(ctx context.Context, cfg *Config) ([]string, error) {
	cfg = cfg.WithDefaults()
	initLogging(cfg)
	return CollectKDD(ctx, cfg)
}
