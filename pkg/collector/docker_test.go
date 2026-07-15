package collector

import (
	"bytes"
	"encoding/binary"
	"testing"
	"testing/iotest"
)

// buildFrame builds a single Docker multiplexed-stream frame (8-byte header + payload)
// for the given stream type (1 = stdout, 2 = stderr).
func buildFrame(streamType byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, []byte(payload)...)
}

func TestDecodeDockerMultiplexedStream(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name:  "short line under 8 bytes",
			lines: []string{"ok\n"},
		},
		{
			name:  "line starting with a date resembling the old byte pattern",
			lines: []string{"2022/06/01 12:00:00 [error] something broke\n"},
		},
		{
			name:  "mixed short and long lines",
			lines: []string{"ok\n", "2022/06/01 12:00:00 [error] something broke\n", "a longer line that is well over eight bytes\n"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stream bytes.Buffer
			var want bytes.Buffer
			for _, line := range tc.lines {
				stream.Write(buildFrame(1, line))
				want.WriteString(line)
			}

			got, err := decodeDockerMultiplexedStream(&stream)
			if err != nil {
				t.Fatalf("decodeDockerMultiplexedStream returned error: %v", err)
			}

			if string(got) != want.String() {
				t.Errorf("decodeDockerMultiplexedStream() = %q, want %q", got, want.String())
			}
		})
	}
}

func TestDecodeDockerMultiplexedStream_SplitReads(t *testing.T) {
	payload := "a payload split across many single-byte reads\n"
	frame := buildFrame(1, payload)

	// Wrap in a reader that only ever returns one byte per Read call, simulating
	// the short-read behavior that previously broke the hand-rolled header peek.
	reader := iotest.OneByteReader(bytes.NewReader(frame))

	got, err := decodeDockerMultiplexedStream(reader)
	if err != nil {
		t.Fatalf("decodeDockerMultiplexedStream returned error: %v", err)
	}

	if string(got) != payload {
		t.Errorf("decodeDockerMultiplexedStream() = %q, want %q", got, payload)
	}
}

func TestDecodeDockerMultiplexedStream_StdoutAndStderrInterleaved(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(buildFrame(1, "stdout line\n"))
	stream.Write(buildFrame(2, "stderr line\n"))

	got, err := decodeDockerMultiplexedStream(&stream)
	if err != nil {
		t.Fatalf("decodeDockerMultiplexedStream returned error: %v", err)
	}

	want := "stdout line\nstderr line\n"
	if string(got) != want {
		t.Errorf("decodeDockerMultiplexedStream() = %q, want %q", got, want)
	}
}
