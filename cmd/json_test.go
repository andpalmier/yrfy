package cmd

import (
	"io"
	"os"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrintJSONUsesIndentedStream(t *testing.T) {
	got := captureStdout(t, func() {
		printJSON(map[string]string{"a": "b"})
	})
	want := "{\n    \"a\": \"b\"\n}\n"
	if got != want {
		t.Fatalf("printJSON output = %q, want %q", got, want)
	}
}
