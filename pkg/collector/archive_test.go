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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// readArchiveEntryNames extracts the list of tar entry names from a tar.gz archive.
func readArchiveEntryNames(t *testing.T, archivePath string) []string {
	t.Helper()

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("creating gzip reader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var names []string
	for {
		header, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, header.Name)
	}
	return names
}

func TestCreateArchivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions are not meaningful on windows")
	}

	dir := t.TempDir()
	filePath := filepath.Join(dir, "ps")
	if err := os.WriteFile(filePath, []byte("some diagnostic output"), 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	archivePath, err := CreateArchive([]string{filePath}, dir)
	if err != nil {
		t.Fatalf("CreateArchive() error: %v", err)
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("stat archive: %v", err)
	}

	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("archive permissions = %o, want 0600", got)
	}
}

func TestCreateArchiveDeduplicatesFiles(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "hosts")
	if err := os.WriteFile(filePath, []byte("127.0.0.1 localhost"), 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// The same path appended twice, simulating the same source file being
	// added to filesToZip more than once.
	archivePath, err := CreateArchive([]string{filePath, filePath}, dir)
	if err != nil {
		t.Fatalf("CreateArchive() error: %v", err)
	}

	names := readArchiveEntryNames(t, archivePath)

	count := 0
	for _, name := range names {
		if name == "hosts" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("archive contains %d entries named %q, want 1 (names: %v)", count, "hosts", names)
	}
}
