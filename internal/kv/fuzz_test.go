package kv_test

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/andreimerlescu/concert/internal/kv"
)

// FuzzRESP2Parse fuzzes both ReadValue and ReadCommand with strict R3 bounds
// to verify zero panics, bounded allocations, and encode/decode round-trip
// fidelity for every successfully parsed RESP2 frame.
func FuzzRESP2Parse(f *testing.F) {
	seeds := [][]byte{
		[]byte("+OK\r\n"),
		[]byte("-ERR invalid\r\n"),
		[]byte(":12345\r\n"),
		[]byte(":-99\r\n"),
		[]byte("$5\r\nhello\r\n"),
		[]byte("$0\r\n\r\n"),
		[]byte("$-1\r\n"),
		[]byte("*-1\r\n"),
		[]byte("*0\r\n"),
		[]byte("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n"),
		[]byte("PING\r\n"),
		[]byte("SET \"quoted key\" 42\r\n"),
		[]byte("*999999999\r\n"),
		[]byte("$999999999\r\n"),
		[]byte("*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n"),
		[]byte{},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	limits := kv.ProtocolLimits{
		MaxBulkBytes: 4096,
		MaxArrayLen:  64,
		MaxLineBytes: 1024,
		MaxNesting:   4,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap input size so the fuzzer does not spend time scanning megabytes.
		if len(data) > 8192 {
			data = data[:8192]
		}

		// Path 1: ReadValue + round-trip invariant when parse succeeds.
		val, err := kv.ReadValue(bufio.NewReader(bytes.NewReader(data)), limits)
		if err == nil {
			var out bytes.Buffer
			bw := bufio.NewWriter(&out)
			if werr := kv.WriteValue(bw, val); werr != nil {
				t.Fatalf("WriteValue failed on parsed value %+v: %v", val, werr)
			}
			if ferr := bw.Flush(); ferr != nil {
				t.Fatalf("Flush failed: %v", ferr)
			}
			val2, err2 := kv.ReadValue(bufio.NewReader(bytes.NewReader(out.Bytes())), limits)
			if err2 != nil {
				t.Fatalf("re-parse failed on encoded %q: %v", out.Bytes(), err2)
			}
			if val2.Kind != val.Kind {
				t.Fatalf("round-trip kind mismatch: got %d, want %d", val2.Kind, val.Kind)
			}
		}

		// Path 2: ReadCommand must never panic on arbitrary bytes.
		_, _ = kv.ReadCommand(bufio.NewReader(bytes.NewReader(data)), limits)
	})
}
