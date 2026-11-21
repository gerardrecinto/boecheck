package boe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is one input file.
type File struct {
	Name string
	Data []byte
}

// Options control a scan.
type Options struct {
	Skip map[string]bool // check IDs to leave out
}

type doc struct {
	file, kind, name, ns string
	node                 *yaml.Node
}

func (d doc) ref() string { return d.kind + "/" + d.name }

// Scan runs every check over the files and returns evidence, sorted by file and line.
func Scan(files []File, opt Options) ([]Result, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	var docs []doc
	var tf []tfRes
	var out []Result
	for _, f := range files {
		if strings.HasSuffix(f.Name, ".tf") {
			tf = append(tf, parseTF(f.Name, f.Data)...)
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(f.Data))
		for {
			var n yaml.Node
			err := dec.Decode(&n)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name, err)
			}
			if len(n.Content) == 0 {
				continue
			}
			root := n.Content[0]
			switch root.Kind {
			case yaml.SequenceNode:
				out = append(out, ansible(f.Name, root)...)
			case yaml.MappingNode:
				meta := child(root, "metadata")
				d := doc{file: f.Name, kind: str(child(root, "kind")), name: str(child(meta, "name")), ns: str(child(meta, "namespace")), node: root}
				if d.kind == "" {
					continue
				}
				if d.ns == "" {
					d.ns = "default"
				}
				docs = append(docs, d)
			}
		}
	}
	for _, d := range docs {
		out = append(out, workloadChecks(d)...)
		out = append(out, secretCheck(d)...)
	}
	out = append(out, namespaceChecks(docs)...)
	out = append(out, terraformChecks(tf)...)

	kept := out[:0]
	for _, r := range out {
		if !opt.Skip[r.Check] {
			kept = append(kept, r)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Check < b.Check
	})
	return kept, nil
}

var workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true, "Job": true, "CronJob": true, "Pod": true}

func podSpec(d doc) (spec, annotations *yaml.Node) {
	switch d.kind {
	case "Pod":
		return path(d.node, "spec"), path(d.node, "metadata", "annotations")
	case "CronJob":
		return path(d.node, "spec", "jobTemplate", "spec", "template", "spec"), path(d.node, "spec", "jobTemplate", "spec", "template", "metadata", "annotations")
	default:
		return path(d.node, "spec", "template", "spec"), path(d.node, "spec", "template", "metadata", "annotations")
	}
}

var sensitiveName = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential)`)

func workloadChecks(d doc) []Result {
	if !workloadKinds[d.kind] {
		return nil
	}
	ps, ann := podSpec(d)
	if ps == nil {
		return nil
	}
	var out []Result
	ref := d.ref()
	var containers []*yaml.Node
	containers = append(containers, items(child(ps, "containers"))...)
	containers = append(containers, items(child(ps, "initContainers"))...)
	podSC := child(ps, "securityContext")
	longRunning := d.kind != "Job" && d.kind != "CronJob"

	type rule struct {
		id    string
		bad   func(c *yaml.Node) string
		scope string
	}
	rules := []rule{
		{"BG001", func(c *yaml.Node) string {
			sc := child(c, "securityContext")
			if isTrue(child(sc, "privileged")) {
				return "privileged: true"
			}
			if !isFalse(child(sc, "allowPrivilegeEscalation")) {
				return "allowPrivilegeEscalation is not false"
			}
			if !isTrue(child(sc, "runAsNonRoot")) && !isTrue(child(podSC, "runAsNonRoot")) {
				return "runAsNonRoot is not true"
			}
			return ""
		}, ""},
		{"BG002", func(c *yaml.Node) string {
			img := str(child(c, "image"))
			if strings.Contains(img, "@sha256:") {
				return ""
			}
			last := img[strings.LastIndex(img, "/")+1:]
			if !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest") {
				return "image " + img + " has no fixed tag"
			}
			return ""
		}, ""},
		{"BG003", func(c *yaml.Node) string {
			l := child(child(c, "resources"), "limits")
			if child(l, "cpu") == nil || child(l, "memory") == nil {
				return "cpu or memory limit missing"
			}
			return ""
		}, ""},
		{"BG005", func(c *yaml.Node) string {
			if !isTrue(path(c, "securityContext", "readOnlyRootFilesystem")) {
				return "readOnlyRootFilesystem is not true"
			}
			return ""
		}, ""},
		{"BG006", func(c *yaml.Node) string {
			for _, e := range items(child(c, "env")) {
				if sensitiveName.MatchString(str(child(e, "name"))) && str(child(e, "value")) != "" {
					return "env " + str(child(e, "name")) + " has a literal value"
				}
			}
			return ""
		}, ""},
	}
	for _, r := range rules {
		failed := false
		for _, c := range containers {
			if r.id == "BG005" && !longRunning {
				continue
			}
			if msg := r.bad(c); msg != "" {
				failed = true
				out = append(out, violation(r.id, d.file, c.Line, ref+" container "+str(child(c, "name")), msg))
			}
		}
		if !failed && len(containers) > 0 {
			out = append(out, mk(r.id, Pass, d.file, ps.Line, ref, "all containers pass"))
		}
	}
	if longRunning {
		missing := false
		for _, c := range items(child(ps, "containers")) {
			if child(c, "readinessProbe") == nil {
				missing = true
				out = append(out, violation("BG004", d.file, c.Line, ref+" container "+str(child(c, "name")), "no readinessProbe"))
			}
		}
		if !missing {
			out = append(out, mk("BG004", Pass, d.file, ps.Line, ref, "readiness probes set"))
		}
	}
	if sa := str(child(ps, "serviceAccountName")); sa == "" || sa == "default" {
		out = append(out, violation("BG010", d.file, ps.Line, ref, "uses the default service account"))
	} else {
		out = append(out, mk("BG010", Pass, d.file, ps.Line, ref, "service account "+sa))
	}
	if d.kind == "Deployment" || d.kind == "StatefulSet" {
		rep := path(d.node, "spec", "replicas")
		n := 1
		if rep != nil {
			fmt.Sscanf(rep.Value, "%d", &n)
		}
		if n < 2 {
			out = append(out, violation("BG011", d.file, d.node.Line, ref, fmt.Sprintf("replicas is %d", n)))
		} else {
			out = append(out, mk("BG011", Pass, d.file, d.node.Line, ref, fmt.Sprintf("replicas is %d", n)))
		}
	}
	if ann != nil && str(child(ann, "vault.hashicorp.com/agent-inject")) == "true" {
		out = append(out, mk("BG012", Pass, d.file, ann.Line, ref, "Vault agent injection enabled"))
	}
	return out
}

func secretCheck(d doc) []Result {
	if d.kind != "Secret" {
		return nil
	}
	for _, k := range []string{"data", "stringData"} {
		if n := child(d.node, k); n != nil && len(n.Content) > 0 {
			return []Result{violation("BG006", d.file, n.Line, d.ref(), "Secret with values committed to the repo")}
		}
	}
	return nil
}

func namespaceChecks(docs []doc) []Result {
	type nsInfo struct {
		first doc
		count int
	}
	spaces := map[string]*nsInfo{}
	var order []string
	for _, d := range docs {
		if workloadKinds[d.kind] {
			if spaces[d.ns] == nil {
				spaces[d.ns] = &nsInfo{first: d}
				order = append(order, d.ns)
			}
			spaces[d.ns].count++
		}
	}
	sort.Strings(order)
	var out []Result
	for _, ns := range order {
		first := spaces[ns].first
		ref := "namespace/" + ns
		// BG007 default-deny NetworkPolicy
		var np *yaml.Node
		for _, d := range docs {
			if d.kind == "NetworkPolicy" && d.ns == ns {
				sel := path(d.node, "spec", "podSelector")
				types := items(path(d.node, "spec", "policyTypes"))
				hasIngress := false
				for _, t := range types {
					hasIngress = hasIngress || t.Value == "Ingress"
				}
				if (sel == nil || len(sel.Content) == 0) && hasIngress && len(items(path(d.node, "spec", "ingress"))) == 0 {
					np = d.node
					out = append(out, mk("BG007", Pass, d.file, d.node.Line, ref, "default-deny ingress policy "+d.name))
					break
				}
			}
		}
		if np == nil {
			out = append(out, violation("BG007", first.file, first.node.Line, ref, "no default-deny NetworkPolicy"))
		}
		// BG008 STRICT mTLS (namespace-wide, or mesh-wide in istio-system)
		found := false
		for _, d := range docs {
			if d.kind != "PeerAuthentication" || (d.ns != ns && d.ns != "istio-system") {
				continue
			}
			if child(child(d.node, "spec"), "selector") != nil {
				continue
			}
			if str(path(d.node, "spec", "mtls", "mode")) == "STRICT" {
				found = true
				out = append(out, mk("BG008", Pass, d.file, d.node.Line, ref, "PeerAuthentication "+d.name+" is STRICT"))
				break
			}
		}
		if !found {
			out = append(out, violation("BG008", first.file, first.node.Line, ref, "no STRICT PeerAuthentication"))
		}
		// BG009 AuthorizationPolicy, not allow-all
		var aps []doc
		for _, d := range docs {
			if d.kind == "AuthorizationPolicy" && d.ns == ns {
				aps = append(aps, d)
			}
		}
		if len(aps) == 0 {
			out = append(out, violation("BG009", first.file, first.node.Line, ref, "no AuthorizationPolicy"))
		}
		for _, d := range aps {
			allowAll := false
			if str(path(d.node, "spec", "action")) != "DENY" {
				for _, r := range items(path(d.node, "spec", "rules")) {
					allowAll = allowAll || (r.Kind == yaml.MappingNode && len(r.Content) == 0)
				}
			}
			if allowAll {
				out = append(out, violation("BG009", d.file, d.node.Line, d.ref(), "ALLOW policy with an empty rule allows all"))
			} else {
				out = append(out, mk("BG009", Pass, d.file, d.node.Line, d.ref(), "policy names its sources"))
			}
		}
	}
	return out
}

// ansible checks plays: a sequence with hosts, tasks or roles on an item.
func ansible(file string, root *yaml.Node) []Result {
	isPlay := false
	for _, it := range root.Content {
		isPlay = isPlay || child(it, "hosts") != nil || child(it, "tasks") != nil || child(it, "import_playbook") != nil
	}
	if !isPlay {
		return nil
	}
	var out []Result
	certBad, credBad := false, false
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.Value == "validate_certs" && isFalse(v) {
					certBad = true
					out = append(out, violation("AN001", file, k.Line, "play", "validate_certs is false"))
				}
				if sensitiveName.MatchString(k.Value) && v.Kind == yaml.ScalarNode && v.Value != "" &&
					v.Tag != "!vault" && !strings.Contains(v.Value, "{{") && !strings.HasPrefix(k.Value, "no_log") {
					credBad = true
					out = append(out, violation("AN002", file, k.Line, "play", k.Value+" has a plain-text value"))
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(root)
	if !certBad {
		out = append(out, mk("AN001", Pass, file, root.Line, "play", "no validate_certs: false"))
	}
	if !credBad {
		out = append(out, mk("AN002", Pass, file, root.Line, "play", "no plain-text credentials"))
	}
	return out
}
