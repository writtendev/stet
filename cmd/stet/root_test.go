package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func executeCommand(args ...string) (string, error) {
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)

	// Reset global flags before execution
	globals.json = false
	globals.verbose = false

	err := cmd.Execute()
	return buf.String(), err
}

func TestRootHelp(t *testing.T) {
	out, err := executeCommand("--help")
	if err != nil {
		t.Fatalf("unexpected error running root --help: %v", err)
	}

	for _, sub := range []string{"sign", "verify", "audit", "version"} {
		if !strings.Contains(out, sub) {
			t.Errorf("expected root help to list subcommand %q, got:\n%s", sub, out)
		}
	}
}

func TestVersionCmd(t *testing.T) {
	t.Run("human output", func(t *testing.T) {
		out, err := executeCommand("version")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "stet") {
			t.Errorf("expected version output to contain 'stet', got: %s", out)
		}
	})

	t.Run("json output", func(t *testing.T) {
		out, err := executeCommand("version", "--json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var payload map[string]string
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid json output: %v, raw: %s", err, out)
		}
		if payload["version"] == "" {
			t.Errorf("expected version field in json, got: %+v", payload)
		}
	})
}

func TestSignCmd(t *testing.T) {
	t.Run("human output default ref", func(t *testing.T) {
		out, err := executeCommand("sign")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "Target Ref") || !strings.Contains(out, "HEAD") {
			t.Errorf("expected sign output to show HEAD ref, got: %s", out)
		}
	})

	t.Run("human output specific ref with push", func(t *testing.T) {
		out, err := executeCommand("sign", "main", "--push")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "main") {
			t.Errorf("expected sign output to show main ref, got: %s", out)
		}
		if !strings.Contains(out, "true") {
			t.Errorf("expected auto-push true, got: %s", out)
		}
	})

	t.Run("json output", func(t *testing.T) {
		out, err := executeCommand("sign", "v1.0.0", "--push", "--json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid json output: %v, raw: %s", err, out)
		}
		if payload["command"] != "sign" || payload["ref"] != "v1.0.0" || payload["push"] != true {
			t.Errorf("unexpected sign json payload: %+v", payload)
		}
	})
}

func TestVerifyCmd(t *testing.T) {
	t.Run("human output", func(t *testing.T) {
		out, err := executeCommand("verify", "HEAD~1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "HEAD~1") {
			t.Errorf("expected verify output to show target ref, got: %s", out)
		}
	})

	t.Run("json output", func(t *testing.T) {
		out, err := executeCommand("verify", "HEAD", "--json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid json output: %v, raw: %s", err, out)
		}
		if payload["command"] != "verify" || payload["ref"] != "HEAD" {
			t.Errorf("unexpected verify json payload: %+v", payload)
		}
	})
}

func TestAuditCmd(t *testing.T) {
	t.Run("human output", func(t *testing.T) {
		out, err := executeCommand("audit")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "stet audit") {
			t.Errorf("expected audit header in output, got: %s", out)
		}
	})

	t.Run("json output", func(t *testing.T) {
		out, err := executeCommand("audit", "--json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid json output: %v, raw: %s", err, out)
		}
		if payload["command"] != "audit" || payload["status"] != "stubbed" {
			t.Errorf("unexpected audit json payload: %+v", payload)
		}
	})
}
