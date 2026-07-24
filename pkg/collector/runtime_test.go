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
	"errors"
	"testing"
)

// withRuntimeDetectors temporarily swaps the package-level detector seams,
// restoring the originals when the test completes.
func withRuntimeDetectors(t *testing.T, docker func([]string) (string, error), kubernetes func([]string) (string, error), vm func(string) (string, string, error)) {
	t.Helper()

	origDocker, origKubernetes, origVM := tryDetectDockerFn, tryDetectKubernetesFn, tryDetectVMFn
	t.Cleanup(func() {
		tryDetectDockerFn, tryDetectKubernetesFn, tryDetectVMFn = origDocker, origKubernetes, origVM
	})

	tryDetectDockerFn, tryDetectKubernetesFn, tryDetectVMFn = docker, kubernetes, vm
}

func TestDetectRuntime_Docker(t *testing.T) {
	withRuntimeDetectors(t,
		func([]string) (string, error) { return RuntimeDocker, nil },
		func([]string) (string, error) {
			t.Fatal("kubernetes detector should not run when docker succeeds")
			return "", nil
		},
		func(string) (string, string, error) {
			t.Fatal("vm detector should not run when docker succeeds")
			return "", "", nil
		},
	)

	got, err := DetectRuntime(nil, "")
	if err != nil {
		t.Fatalf("DetectRuntime() error = %v", err)
	}
	if got != RuntimeDocker {
		t.Errorf("DetectRuntime() = %q, want %q", got, RuntimeDocker)
	}
}

func TestDetectRuntime_FallsBackToKubernetes(t *testing.T) {
	withRuntimeDetectors(t,
		func([]string) (string, error) { return "", errors.New("no docker socket") },
		func([]string) (string, error) { return RuntimeKubernetes, nil },
		func(string) (string, string, error) {
			t.Fatal("vm detector should not run when kubernetes succeeds")
			return "", "", nil
		},
	)

	got, err := DetectRuntime(nil, "")
	if err != nil {
		t.Fatalf("DetectRuntime() error = %v", err)
	}
	if got != RuntimeKubernetes {
		t.Errorf("DetectRuntime() = %q, want %q", got, RuntimeKubernetes)
	}
}

func TestDetectRuntime_FallsBackToVM(t *testing.T) {
	withRuntimeDetectors(t,
		func([]string) (string, error) { return "", errors.New("no docker socket") },
		func([]string) (string, error) { return "", errors.New("no kubeconfig") },
		func(string) (string, string, error) { return RuntimeVM, "/usr/local/kong", nil },
	)

	got, err := DetectRuntime(nil, "")
	if err != nil {
		t.Fatalf("DetectRuntime() error = %v", err)
	}
	if got != RuntimeVM {
		t.Errorf("DetectRuntime() = %q, want %q", got, RuntimeVM)
	}
}

func TestDetectRuntime_AllFail(t *testing.T) {
	withRuntimeDetectors(t,
		func([]string) (string, error) { return "", errors.New("no docker socket") },
		func([]string) (string, error) { return "", errors.New("no kubeconfig") },
		func(string) (string, string, error) { return "", "", errors.New("no .kong_env found") },
	)

	_, err := DetectRuntime(nil, "")
	if err == nil {
		t.Fatal("DetectRuntime() error = nil, want an error when no runtime is detected")
	}
}
