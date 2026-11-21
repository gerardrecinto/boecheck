package boe

import (
	"regexp"
	"strings"
)

type tfLine struct {
	n int
	s string
}

type tfRes struct {
	file, typ, name string
	line            int
	body            []tfLine
}

func (r tfRes) ref() string { return r.typ + "." + r.name }
func (r tfRes) text() string {
	var b strings.Builder
	for _, l := range r.body {
		b.WriteString(l.s + "\n")
	}
	return b.String()
}

var tfHead = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

// parseTF finds resource blocks by counting braces. It is a scanner, not a full HCL parser.
func parseTF(file string, data []byte) []tfRes {
	var out []tfRes
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		m := tfHead.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		r := tfRes{file: file, typ: m[1], name: m[2], line: i + 1}
		depth := 0
		for j := i; j < len(lines); j++ {
			l := lines[j]
			if t := strings.TrimSpace(l); strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
				continue
			}
			depth += strings.Count(l, "{") - strings.Count(l, "}")
			r.body = append(r.body, tfLine{j + 1, l})
			if depth <= 0 {
				i = j
				break
			}
		}
		out = append(out, r)
	}
	return out
}

var (
	reWorld = regexp.MustCompile(`0\.0\.0\.0/0`)
	rePort  = regexp.MustCompile(`from_port\s*=\s*(\d+)`)
	reRet   = regexp.MustCompile(`retention_in_days\s*=\s*[1-9]`)
)

func terraformChecks(rs []tfRes) []Result {
	var out []Result
	refersTo := func(typ string, target tfRes) *tfRes {
		for i := range rs {
			if rs[i].typ == typ && strings.Contains(rs[i].text(), target.ref()+".") {
				return &rs[i]
			}
		}
		return nil
	}
	for _, r := range rs {
		txt := r.text()
		switch r.typ {
		case "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
			for _, seg := range ingressSegments(r) {
				if !reWorld.MatchString(seg.text) {
					continue
				}
				port := rePort.FindStringSubmatch(seg.text)
				if port != nil && port[1] == "443" {
					out = append(out, mk("TF001", Pass, r.file, seg.line, r.ref(), "world-open only on 443"))
					continue
				}
				out = append(out, violation("TF001", r.file, seg.line, r.ref(), "0.0.0.0/0 ingress on a port other than 443"))
			}
		case "aws_s3_bucket":
			if e := refersTo("aws_s3_bucket_server_side_encryption_configuration", r); e != nil {
				out = append(out, mk("TF002", Pass, e.file, e.line, r.ref(), "default encryption configured"))
			} else {
				out = append(out, violation("TF002", r.file, r.line, r.ref(), "no server-side encryption configuration"))
			}
			if p := refersTo("aws_s3_bucket_public_access_block", r); p != nil && strings.Count(p.text(), "= true") >= 4 {
				out = append(out, mk("TF003", Pass, p.file, p.line, r.ref(), "public access blocked"))
			} else {
				out = append(out, violation("TF003", r.file, r.line, r.ref(), "no complete public access block"))
			}
		case "aws_db_instance", "aws_rds_cluster":
			if regexp.MustCompile(`storage_encrypted\s*=\s*true`).MatchString(txt) {
				out = append(out, mk("TF004", Pass, r.file, r.line, r.ref(), "storage_encrypted = true"))
			} else {
				out = append(out, violation("TF004", r.file, r.line, r.ref(), "storage_encrypted is not true"))
			}
		case "aws_cloudwatch_log_group":
			if reRet.MatchString(txt) {
				out = append(out, mk("TF005", Pass, r.file, r.line, r.ref(), "retention set"))
			} else {
				out = append(out, violation("TF005", r.file, r.line, r.ref(), "no retention_in_days, logs never expire"))
			}
		case "aws_ebs_volume":
			if regexp.MustCompile(`\bencrypted\s*=\s*true`).MatchString(txt) {
				out = append(out, mk("TF006", Pass, r.file, r.line, r.ref(), "encrypted = true"))
			} else {
				out = append(out, violation("TF006", r.file, r.line, r.ref(), "encrypted is not true"))
			}
		}
	}
	return out
}

type seg struct {
	line int
	text string
}

// ingressSegments returns the ingress blocks of a security group, or the whole
// rule resource when it is an ingress rule.
func ingressSegments(r tfRes) []seg {
	txt := r.text()
	switch r.typ {
	case "aws_security_group_rule":
		if !regexp.MustCompile(`type\s*=\s*"ingress"`).MatchString(txt) {
			return nil
		}
		return []seg{{r.line, txt}}
	case "aws_vpc_security_group_ingress_rule":
		return []seg{{r.line, txt}}
	}
	var out []seg
	head := regexp.MustCompile(`^\s*ingress\s*(=\s*\[\s*)?\{`)
	for i := 0; i < len(r.body); i++ {
		if !head.MatchString(r.body[i].s) {
			continue
		}
		depth, start := 0, i
		var b strings.Builder
		for ; i < len(r.body); i++ {
			depth += strings.Count(r.body[i].s, "{") - strings.Count(r.body[i].s, "}")
			b.WriteString(r.body[i].s + "\n")
			if depth <= 0 {
				break
			}
		}
		out = append(out, seg{r.body[start].n, b.String()})
	}
	return out
}
