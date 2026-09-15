package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestMainErrorJSON(t *testing.T) {
	// Build the stet binary to test main.go's behavior
	cmd := exec.Command("go", "build", "-o", "stet_test_bin")
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}
	defer func() {
		_ = os.Remove("stet_test_bin")
	}()

	// Run with invalid arguments to trigger an execution error and check for JSON output
	runCmd := exec.Command("./stet_test_bin", "sign", "arg1", "arg2", "--json")
	var stderr bytes.Buffer
	runCmd.Stderr = &stderr
	err := runCmd.Run()
	
	if err == nil {
		t.Fatalf("expected command to fail, but it succeeded")
	}

	var payload map[string]string
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON output on stderr, got %q (unmarshal error: %v)", stderr.String(), err)
	}
	
	if payload["error"] == "" {
		t.Errorf("expected 'error' key in JSON output, got: %v", payload)
	}
}
