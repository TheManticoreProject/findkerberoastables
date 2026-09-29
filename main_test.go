package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestRequestWritesNoBannerToStdout(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "request", "-d", "example.local", "-u", "test", "-dc", "127.0.0.1", "--no-pass")
	output, err := cmd.Output()
	if err == nil {
		t.Fatal("request without credentials unexpectedly succeeded")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || !strings.Contains(string(exitErr.Stderr), "request mode requires a password or NT hash") {
		t.Fatalf("unexpected command error: %v", err)
	}
	if len(output) != 0 {
		t.Fatalf("request wrote %q to stdout before producing hashes", output)
	}
}
