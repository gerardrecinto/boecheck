package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func do(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var o, e bytes.Buffer
	c := run(args, strings.NewReader(stdin), &o, &e)
	return c, o.String(), e.String()
}

func TestScanExitCodes(t *testing.T) {
	if c, _, _ := do(t, "", "scan", "../../examples/good"); c != 0 {
		t.Errorf("good: exit %d", c)
	}
	if c, out, _ := do(t, "", "scan", "../../examples/bad"); c != 1 || !strings.Contains(out, "FAIL BG001") {
		t.Errorf("bad: exit %d\n%s", c, out)
	}
	if c, _, _ := do(t, "", "scan", "../../examples/nope"); c != 2 {
		t.Errorf("missing path: exit %d", c)
	}
	if c, _, _ := do(t, ""); c != 2 {
		t.Errorf("no args: exit %d", c)
	}
}

func TestStrictFailsOnWarnings(t *testing.T) {
	y := "apiVersion: v1\nkind: Pod\nmetadata: {name: a}\nspec:\n  serviceAccountName: a\n  securityContext: {runAsNonRoot: true}\n  containers:\n    - name: c\n      image: 'a:1'\n      resources: {limits: {cpu: 1, memory: 1Gi}}\n      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true}\n"
	if c, _, _ := do(t, y, "scan", "--skip", "BG004,BG007,BG008,BG009", "-"); c != 0 {
		t.Fatalf("expected a clean run, exit %d", c)
	}
	if c, _, _ := do(t, y, "scan", "--skip", "BG007,BG008,BG009", "--strict", "-"); c != 1 {
		t.Fatalf("--strict should fail on the missing probe, exit %d", c)
	}
}

func TestStdinAndBoEFile(t *testing.T) {
	b, _ := os.ReadFile("../../examples/good/k8s.yaml")
	out := filepath.Join(t.TempDir(), "boe.md")
	if c, _, e := do(t, string(b), "scan", "--boe", out, "-"); c != 0 {
		t.Fatalf("exit %d %s", c, e)
	}
	md, _ := os.ReadFile(out)
	if !strings.Contains(string(md), "SC-8 Transmission Confidentiality") {
		t.Error("BoE file missing the SC-8 section")
	}
}

func TestJSONOutput(t *testing.T) {
	_, out, _ := do(t, "", "scan", "--json", "../../examples/bad/main.tf")
	if !strings.Contains(out, `"check": "TF004"`) || !strings.Contains(out, `"nist80053r5"`) {
		t.Errorf("unexpected json:\n%s", out)
	}
}

func TestSLOAndRunbookCommands(t *testing.T) {
	if c, out, _ := do(t, "", "slo", "../../examples/slo.yaml"); c != 0 || !strings.Contains(out, "alert: SLOBurnRatePage1H") {
		t.Errorf("slo: exit %d\n%s", c, out)
	}
	if c, out, _ := do(t, "", "runbook", "../../examples/slo.yaml"); c != 0 || !strings.Contains(out, "# Runbook: checkout") {
		t.Errorf("runbook: exit %d", c)
	}
	bad := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(bad, []byte("service: a\nslos: []\n"), 0o644)
	if c, _, e := do(t, "", "slo", bad); c != 2 || !strings.Contains(e, "no slos") {
		t.Errorf("bad slo: exit %d %s", c, e)
	}
}
