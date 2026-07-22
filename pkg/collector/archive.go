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
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// CreateArchive creates a tar.gz archive from the given files.
// When outputDir is non-empty, the archive is written to that directory.
// Returns the path to the created archive.
func CreateArchive(filesToWrite []string, outputDir string) (string, error) {
	if len(filesToWrite) == 0 {
		log.Warn("No files to write to archive")
		return "", nil
	}

	outputName := fmt.Sprintf("%s-support.tar.gz", time.Now().Format("2006-01-02-15-04-05"))

	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("creating output directory %s: %w", outputDir, err)
		}
		outputName = filepath.Join(outputDir, outputName)
	}

	log.WithField("filename", outputName).Info("Creating archive")

	output, err := createSecureFile(outputName)
	if err != nil {
		log.WithError(err).Error("Failed to create output file")
		return "", err
	}

	defer func() {
		if err := output.Close(); err != nil {
			log.WithError(err).Error("Error closing output file")
		}
	}()

	// Create the archive and write the output
	gw := gzip.NewWriter(output)
	defer func() {
		if err := gw.Close(); err != nil {
			log.WithError(err).Error("Error closing gzip writer")
		}
	}()

	tw := tar.NewWriter(gw)
	defer func() {
		if err := tw.Close(); err != nil {
			log.WithError(err).Error("Error closing tar writer")
		}
	}()

	// Iterate over files and add them to the tar archive, skipping any duplicate
	// paths so the same source file is never written into the archive twice.
	seen := make(map[string]struct{}, len(filesToWrite))
	for _, file := range filesToWrite {
		if _, dup := seen[file]; dup {
			log.WithField("file", file).Debug("Skipping duplicate file already added to archive")
			continue
		}
		seen[file] = struct{}{}

		err := addToArchive(tw, file)
		if err != nil {
			log.WithFields(log.Fields{
				"file":  file,
				"error": err,
			}).Error("Error adding file to archive")
			return "", err
		}
	}

	log.WithField("filename", output.Name()).Info("Diagnostics have been written to archive")

	return outputName, nil
}

// addToArchive adds a single file to the tar archive.
func addToArchive(tw *tar.Writer, filename string) error {
	log.WithField("filename", filename).Debug("Adding file to archive")

	// Open the file which will be written into the archive
	file, err := os.Open(filename)
	if err != nil {
		return err
	}

	defer func() {
		if err := file.Close(); err != nil {
			log.WithFields(log.Fields{
				"filename": filename,
				"error":    err,
			}).Error("Error closing file")
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

	// Store only the basename in the archive - source files live under a
	// temporary workDir whose path must not leak into the tar entry names.
	header.Name = filepath.Base(filename)

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

// WriteOutputToFile writes data to a file with the specified filename.
func WriteOutputToFile(filename string, data []byte) error {
	log.WithField("filename", filename).Debug("Writing output to file")
	err := os.WriteFile(filename, data, 0600)
	if err != nil {
		return err
	}
	return nil
}

// createSecureFile creates (or truncates) a file for writing with 0600
// permissions. Collected diagnostic output routinely contains credentials, so
// none of it should be created with the default, world-readable 0666 that
// os.Create would otherwise apply.
func createSecureFile(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}
