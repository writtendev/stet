package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestUIFormatting(t *testing.T) {
	if h := Header("test header"); !strings.Contains(h, "TEST HEADER") {
		t.Errorf("expected uppercase header, got: %s", h)
	}

	if kv := KeyValue("Ref", "HEAD"); !strings.Contains(kv, "Ref") || !strings.Contains(kv, "HEAD") {
		t.Errorf("expected key and val in output, got: %s", kv)
	}

	if s := Success("done"); !strings.Contains(s, "✓") || !strings.Contains(s, "done") {
		t.Errorf("expected checkmark in success message, got: %s", s)
	}

	if w := Warn("caution"); !strings.Contains(w, "!") || !strings.Contains(w, "caution") {
		t.Errorf("expected exclamation in warn message, got: %s", w)
	}

	if e := Error("failed"); !strings.Contains(e, "✗") || !strings.Contains(e, "failed") {
		t.Errorf("expected cross in error message, got: %s", e)
	}

	buf := new(bytes.Buffer)
	if err := FprintDivider(buf, 20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "─") {
		t.Errorf("expected divider line, got: %s", buf.String())
	}
}
