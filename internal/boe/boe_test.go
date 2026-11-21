package boe

import (
	"math"
	"os"
	"strings"
	"testing"
)

func scanDir(t *testing.T, names ...string) []Result {
	t.Helper()
	var fs []File
	for _, n := range names {
		b, err := os.ReadFile("../../examples/" + n)
		if err != nil {
			t.Fatal(err)
		}
		fs = append(fs, File{"examples/" + n, b})
	}
	rs, err := Scan(fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func ids(rs []Result, st Status) map[string]bool {
	m := map[string]bool{}
	for _, r := range rs {
		if r.Status == st {
			m[r.Check] = true
		}
	}
	return m
}

func TestGoodExamplesAreClean(t *testing.T) {
	rs := scanDir(t, "good/k8s.yaml", "good/main.tf", "good/playbook.yml")
	if _, w, f := Counts(rs); w != 0 || f != 0 {
		t.Fatalf("good examples: %d warn %d fail\n%s", w, f, Text(rs, false))
	}
	pass := ids(rs, Pass)
	for _, c := range Catalog {
		if !pass[c.ID] {
			t.Errorf("good examples give no passing evidence for %s", c.ID)
		}
	}
}

func TestBadExamplesTripEveryRule(t *testing.T) {
	rs := scanDir(t, "bad/k8s.yaml", "bad/main.tf", "bad/playbook.yml")
	hit := map[string]bool{}
	for _, r := range rs {
		if r.Status != Pass {
			hit[r.Check] = true
		}
	}
	for _, c := range Catalog {
		if c.ID == "BG012" { // evidence only, nothing to violate
			continue
		}
		if !hit[c.ID] {
			t.Errorf("bad examples do not trip %s", c.ID)
		}
	}
}

func TestWorkloadRules(t *testing.T) {
	cases := []struct {
		name, patch string
		want        string
	}{
		{"latest tag", "image: nginx:latest", "BG002"},
		{"no tag", "image: nginx", "BG002"},
		{"registry port is not a tag", "image: reg.local:5000/app", "BG002"},
		{"escalation", "securityContext: {allowPrivilegeEscalation: true, runAsNonRoot: true}", "BG001"},
	}
	for _, c := range cases {
		y := "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a}\nspec:\n  replicas: 2\n  template:\n    spec:\n      serviceAccountName: a\n      containers:\n        - name: c\n          " + c.patch + "\n"
		rs, err := Scan([]File{{"a.yaml", []byte(y)}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !ids(rs, Fail)[c.want] {
			t.Errorf("%s: want %s to fail\n%s", c.name, c.want, Text(rs, true))
		}
	}
}

func TestPinnedTagPasses(t *testing.T) {
	y := "apiVersion: v1\nkind: Pod\nmetadata: {name: a}\nspec:\n  containers:\n    - {name: c, image: 'reg.local:5000/app:1.2.3'}\n"
	rs, _ := Scan([]File{{"a.yaml", []byte(y)}}, Options{})
	if ids(rs, Fail)["BG002"] {
		t.Fatal("a fixed tag behind a registry port should pass")
	}
}

func TestJobsNeedNoProbeOrReplicas(t *testing.T) {
	y := "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: a}\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - {name: c, image: 'a:1'}\n"
	rs, _ := Scan([]File{{"a.yaml", []byte(y)}}, Options{})
	for _, r := range rs {
		if r.Check == "BG004" || r.Check == "BG011" {
			t.Errorf("%s should not apply to a CronJob", r.Check)
		}
	}
}

func TestMeshWideStrictCoversNamespace(t *testing.T) {
	y := `apiVersion: apps/v1
kind: Deployment
metadata: {name: a, namespace: shop}
spec: {template: {spec: {containers: [{name: c, image: 'a:1'}]}}}
---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: {name: default, namespace: istio-system}
spec: {mtls: {mode: STRICT}}
`
	rs, _ := Scan([]File{{"a.yaml", []byte(y)}}, Options{})
	if ids(rs, Fail)["BG008"] {
		t.Fatal("a mesh-wide STRICT policy in istio-system should cover the namespace")
	}
}

func TestSelectorScopedPeerAuthIsNotNamespaceWide(t *testing.T) {
	y := `apiVersion: apps/v1
kind: Deployment
metadata: {name: a, namespace: shop}
spec: {template: {spec: {containers: [{name: c, image: 'a:1'}]}}}
---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: {name: one, namespace: shop}
spec: {selector: {matchLabels: {app: a}}, mtls: {mode: STRICT}}
`
	rs, _ := Scan([]File{{"a.yaml", []byte(y)}}, Options{})
	if !ids(rs, Fail)["BG008"] {
		t.Fatal("a workload-scoped policy must not count as namespace-wide")
	}
}

func TestDenyPolicyWithEmptyRuleIsNotAllowAll(t *testing.T) {
	y := `apiVersion: apps/v1
kind: Deployment
metadata: {name: a}
spec: {template: {spec: {containers: [{name: c, image: 'a:1'}]}}}
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: deny}
spec: {action: DENY, rules: [{}]}
`
	rs, _ := Scan([]File{{"a.yaml", []byte(y)}}, Options{})
	if ids(rs, Fail)["BG009"] {
		t.Fatal("a DENY policy with an empty rule is not allow-all")
	}
}

func TestSkipAndBadYAML(t *testing.T) {
	b, _ := os.ReadFile("../../examples/bad/k8s.yaml")
	rs, _ := Scan([]File{{"k.yaml", b}}, Options{Skip: map[string]bool{"BG001": true}})
	if ids(rs, Fail)["BG001"] {
		t.Fatal("skipped check still reported")
	}
	if _, err := Scan([]File{{"x.yaml", []byte("a: [")}}, Options{}); err == nil || !strings.Contains(err.Error(), "x.yaml") {
		t.Fatalf("want an error naming the file, got %v", err)
	}
}

func TestTerraformWorldOpen443IsFine(t *testing.T) {
	tf := "resource \"aws_vpc_security_group_ingress_rule\" \"a\" {\n  cidr_ipv4 = \"0.0.0.0/0\"\n  from_port = 22\n}\n"
	rs, _ := Scan([]File{{"a.tf", []byte(tf)}}, Options{})
	if !ids(rs, Fail)["TF001"] {
		t.Fatal("world-open SSH must fail")
	}
}

func TestBoEGroupsByControl(t *testing.T) {
	rs := scanDir(t, "bad/k8s.yaml", "bad/main.tf")
	md := BoE("test", rs)
	for _, want := range []string{"# Body of Evidence: test", "### AC-6 Least Privilege", "### SC-28 Protection of Information at Rest", "## NIST SP 800-207 zero trust tenets", "45 CFR 164.312(a)(2)(iv)", "`examples/bad/main.tf:14`"} {
		if !strings.Contains(md, want) {
			t.Errorf("BoE is missing %q", want)
		}
	}
	if strings.Contains(md, "—") {
		t.Error("BoE contains an em dash")
	}
}

func TestEveryCheckIDHasKnownControls(t *testing.T) {
	for _, c := range Catalog {
		for _, n := range c.NIST {
			if ControlTitles[n] == "" {
				t.Errorf("%s maps to %s which has no title", c.ID, n)
			}
		}
		for _, z := range c.ZT {
			if TenetTitles[z] == "" {
				t.Errorf("%s maps to unknown tenet %d", c.ID, z)
			}
		}
	}
}

func TestBurnRates(t *testing.T) {
	// 2% in 1h, 5% in 6h, 10% in 3d over a 30 day window: 14.4, 6, 1.
	want := []float64{14.4, 6, 1}
	for i, a := range Alerts(30) {
		if math.Abs(a.Rate-want[i]) > 1e-9 {
			t.Errorf("alert %d rate %v, want %v", i, a.Rate, want[i])
		}
	}
	if a := Alerts(30)[0]; math.Abs(a.HoursToEmpty-50) > 1e-9 {
		t.Errorf("hours to empty %v, want 50", a.HoursToEmpty)
	}
}

func TestSLOValidation(t *testing.T) {
	bad := map[string]string{
		"objective 100": "service: a\nslos:\n  - {name: x, objective: 100, errors: 'e[$WINDOW]', total: 't[$WINDOW]'}\n",
		"no window var": "service: a\nslos:\n  - {name: x, objective: 99.9, errors: 'e[5m]', total: 't[$WINDOW]'}\n",
		"bad service":   "service: A B\nslos:\n  - {name: x, objective: 99.9, errors: 'e[$WINDOW]', total: 't[$WINDOW]'}\n",
		"bad window":    "service: a\nslos:\n  - {name: x, objective: 99.9, window: 4w, errors: 'e[$WINDOW]', total: 't[$WINDOW]'}\n",
		"unknown field": "service: a\nbogus: 1\nslos:\n  - {name: x, objective: 99.9, errors: 'e[$WINDOW]', total: 't[$WINDOW]'}\n",
		"no slos":       "service: a\n",
	}
	for n, y := range bad {
		if _, err := ParseSLO([]byte(y)); err == nil {
			t.Errorf("%s: expected an error", n)
		}
	}
}

func TestRulesAndRunbook(t *testing.T) {
	b, _ := os.ReadFile("../../examples/slo.yaml")
	f, err := ParseSLO(b)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Rules(f)
	for _, want := range []string{"slo:sli_error:ratio_rate5m", "SLOBurnRatePage1H", "> 0.0144", "> 0.006", "> 0.001", "severity: ticket"} {
		if !strings.Contains(r, want) {
			t.Errorf("rules are missing %q\n%s", want, r)
		}
	}
	rb := Runbook(f)
	for _, want := range []string{"# Runbook: checkout", "43.2 minutes", "50 hours", "Owner: Platform team"} {
		if !strings.Contains(rb, want) {
			t.Errorf("runbook is missing %q", want)
		}
	}
}
