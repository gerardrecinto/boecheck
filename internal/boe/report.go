package boe

import (
	"fmt"
	"sort"
	"strings"
)

// Counts tallies results by status.
func Counts(rs []Result) (pass, warn, fail int) {
	for _, r := range rs {
		switch r.Status {
		case Pass:
			pass++
		case Warn:
			warn++
		case Fail:
			fail++
		}
	}
	return
}

func worst(rs []Result) Status {
	s := Pass
	for _, r := range rs {
		if r.Status == Fail {
			return Fail
		}
		if r.Status == Warn {
			s = Warn
		}
	}
	return s
}

func rows(b *strings.Builder, rs []Result) {
	b.WriteString("| Status | Check | Resource | Evidence |\n|---|---|---|---|\n")
	for _, r := range rs {
		fmt.Fprintf(b, "| %s | %s | %s | `%s:%d` %s |\n", strings.ToUpper(string(r.Status)), r.Check, r.Resource, r.File, r.Line, r.Message)
	}
	b.WriteString("\n")
}

// BoE renders the Body of Evidence as Markdown: results grouped by NIST SP
// 800-53r5 control, then by 800-207 tenet and HIPAA safeguard.
func BoE(title string, rs []Result) string {
	var b strings.Builder
	p, w, f := Counts(rs)
	fmt.Fprintf(&b, "# Body of Evidence: %s\n\n", title)
	b.WriteString("This is evidence of configuration found in the scanned files. It does not show how the system runs, and the check-to-control mapping is a reading, not an official crosswalk. An assessor decides what counts.\n\n")
	fmt.Fprintf(&b, "Results: %d pass, %d warn, %d fail.\n\n", p, w, f)

	byCtl := map[string][]Result{}
	byTenet := map[int][]Result{}
	byHIPAA := map[string][]Result{}
	for _, r := range rs {
		for _, c := range r.NIST {
			byCtl[c] = append(byCtl[c], r)
		}
		for _, t := range r.ZT {
			byTenet[t] = append(byTenet[t], r)
		}
		for _, h := range r.HIPAA {
			byHIPAA[h] = append(byHIPAA[h], r)
		}
	}
	b.WriteString("## NIST SP 800-53r5 controls\n\n| Control | Title | Status | Pass | Warn | Fail |\n|---|---|---|---|---|---|\n")
	var ctls []string
	for c := range byCtl {
		ctls = append(ctls, c)
	}
	sort.Strings(ctls)
	for _, c := range ctls {
		cp, cw, cf := Counts(byCtl[c])
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d |\n", c, ControlTitles[c], strings.ToUpper(string(worst(byCtl[c]))), cp, cw, cf)
	}
	b.WriteString("\n")
	for _, c := range ctls {
		fmt.Fprintf(&b, "### %s %s\n\n", c, ControlTitles[c])
		rows(&b, byCtl[c])
	}
	if len(byTenet) > 0 {
		b.WriteString("## NIST SP 800-207 zero trust tenets\n\n")
		var ts []int
		for t := range byTenet {
			ts = append(ts, t)
		}
		sort.Ints(ts)
		for _, t := range ts {
			fmt.Fprintf(&b, "### Tenet %d: %s\n\nStatus: %s\n\n", t, TenetTitles[t], strings.ToUpper(string(worst(byTenet[t]))))
			rows(&b, byTenet[t])
		}
	}
	if len(byHIPAA) > 0 {
		b.WriteString("## HIPAA Security Rule safeguards\n\n")
		var hs []string
		for h := range byHIPAA {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		for _, h := range hs {
			fmt.Fprintf(&b, "### 45 CFR %s\n\nStatus: %s\n\n", h, strings.ToUpper(string(worst(byHIPAA[h]))))
			rows(&b, byHIPAA[h])
		}
	}
	return b.String()
}

// Text renders failures and warnings for a terminal, with fixes.
func Text(rs []Result, verbose bool) string {
	var b strings.Builder
	for _, r := range rs {
		if r.Status == Pass && !verbose {
			continue
		}
		fmt.Fprintf(&b, "%s %s %s:%d %s: %s\n", strings.ToUpper(string(r.Status)), r.Check, r.File, r.Line, r.Resource, r.Message)
		if r.Fix != "" {
			fmt.Fprintf(&b, "     fix: %s  [%s]\n", r.Fix, strings.Join(r.NIST, ", "))
		}
	}
	p, w, f := Counts(rs)
	fmt.Fprintf(&b, "%d checks: %d pass, %d warn, %d fail\n", len(rs), p, w, f)
	return b.String()
}
