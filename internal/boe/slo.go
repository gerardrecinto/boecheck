package boe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SLOFile is the input for rule and runbook generation.
type SLOFile struct {
	Service   string `yaml:"service"`
	Owner     string `yaml:"owner"`
	Dashboard string `yaml:"dashboard"`
	SLOs      []SLO  `yaml:"slos"`
}

type SLO struct {
	Name      string  `yaml:"name"`
	Objective float64 `yaml:"objective"` // percent, for example 99.9
	Window    string  `yaml:"window"`    // days, for example 30d
	Errors    string  `yaml:"errors"`    // PromQL rate of bad events, with $WINDOW
	Total     string  `yaml:"total"`     // PromQL rate of all events, with $WINDOW
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func ParseSLO(b []byte) (*SLOFile, error) {
	var f SLOFile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(f.Service) {
		return nil, fmt.Errorf("service %q must be lowercase letters, digits, - or _", f.Service)
	}
	if len(f.SLOs) == 0 {
		return nil, fmt.Errorf("no slos")
	}
	for i := range f.SLOs {
		s := &f.SLOs[i]
		if s.Window == "" {
			s.Window = "30d"
		}
		if !nameRe.MatchString(s.Name) {
			return nil, fmt.Errorf("slo name %q must be lowercase letters, digits, - or _", s.Name)
		}
		if s.Objective <= 0 || s.Objective >= 100 {
			return nil, fmt.Errorf("slo %s: objective %v must be between 0 and 100 (exclusive)", s.Name, s.Objective)
		}
		if _, err := days(s.Window); err != nil {
			return nil, fmt.Errorf("slo %s: %w", s.Name, err)
		}
		for _, q := range []string{s.Errors, s.Total} {
			if !strings.Contains(q, "$WINDOW") {
				return nil, fmt.Errorf("slo %s: errors and total queries must use $WINDOW as the range, for example [$WINDOW]", s.Name)
			}
		}
	}
	return &f, nil
}

func days(w string) (int, error) {
	if !strings.HasSuffix(w, "d") {
		return 0, fmt.Errorf("window %q must be a number of days like 30d", w)
	}
	n, err := strconv.Atoi(strings.TrimSuffix(w, "d"))
	if err != nil || n < 1 {
		return 0, fmt.Errorf("window %q must be a number of days like 30d", w)
	}
	return n, nil
}

// Alert is one multi-window burn-rate alert.
type Alert struct {
	Severity     string
	Rate         float64 // burn rate multiple
	Long, Short  string  // look-back windows
	BudgetPct    float64 // share of the error budget used when it fires
	For          string
	HoursToEmpty float64
}

// Alerts returns the burn-rate alerts for a window of n days. The rate for a
// share of budget spent over a look-back is share * window hours / look-back hours.
func Alerts(n int) []Alert {
	w := float64(n * 24)
	mk := func(sev string, pct float64, lookH float64, long, short, f string) Alert {
		r := pct / 100 * w / lookH
		return Alert{sev, r, long, short, pct, f, w / r}
	}
	return []Alert{
		mk("page", 2, 1, "1h", "5m", "2m"),
		mk("page", 5, 6, "6h", "30m", "2m"),
		mk("ticket", 10, 72, "3d", "6h", "15m"),
	}
}

type rule struct {
	Record      string            `yaml:"record,omitempty"`
	Alert       string            `yaml:"alert,omitempty"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}
type group struct {
	Name  string `yaml:"name"`
	Rules []rule `yaml:"rules"`
}

func g(x float64) string { return strconv.FormatFloat(x, 'g', 10, 64) }

// Rules renders Prometheus recording and alerting rules.
func Rules(f *SLOFile) (string, error) {
	var groups []group
	for _, s := range f.SLOs {
		n, _ := days(s.Window)
		lbl := map[string]string{"service": f.Service, "slo": s.Name}
		sel := fmt.Sprintf(`{service=%q,slo=%q}`, f.Service, s.Name)
		budget := 1 - s.Objective/100
		gr := group{Name: "slo-" + f.Service + "-" + s.Name}
		seen := map[string]bool{}
		for _, a := range Alerts(n) {
			for _, w := range []string{a.Long, a.Short} {
				if seen[w] {
					continue
				}
				seen[w] = true
				e := strings.ReplaceAll(s.Errors, "$WINDOW", w)
				t := strings.ReplaceAll(s.Total, "$WINDOW", w)
				gr.Rules = append(gr.Rules, rule{Record: "slo:sli_error:ratio_rate" + w, Expr: "(" + e + ") / (" + t + ")", Labels: lbl})
			}
		}
		for _, a := range Alerts(n) {
			thr := g(a.Rate * budget)
			name := "SLOBurnRate" + strings.ToUpper(a.Severity[:1]) + a.Severity[1:]
			gr.Rules = append(gr.Rules, rule{
				Alert:  name + strings.ToUpper(a.Long),
				Expr:   fmt.Sprintf("slo:sli_error:ratio_rate%s%s > %s and slo:sli_error:ratio_rate%s%s > %s", a.Long, sel, thr, a.Short, sel, thr),
				For:    a.For,
				Labels: map[string]string{"severity": a.Severity, "service": f.Service, "slo": s.Name},
				Annotations: map[string]string{
					"summary":     fmt.Sprintf("%s %s is burning its error budget %sx too fast", f.Service, s.Name, g(a.Rate)),
					"description": fmt.Sprintf("Objective %s%% over %s. At this rate the budget is gone in %s hours. See RUNBOOK.md.", g(s.Objective), s.Window, g(a.HoursToEmpty)),
				},
			})
		}
		groups = append(groups, gr)
	}
	b, err := yaml.Marshal(map[string]any{"groups": groups})
	return string(b), err
}

// Runbook renders a Markdown runbook for the alerts Rules produces.
func Runbook(f *SLOFile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Runbook: %s\n\n", f.Service)
	if f.Owner != "" {
		fmt.Fprintf(&b, "Owner: %s\n\n", f.Owner)
	}
	if f.Dashboard != "" {
		fmt.Fprintf(&b, "Dashboard: %s\n\n", f.Dashboard)
	}
	for _, s := range f.SLOs {
		n, _ := days(s.Window)
		mins := (1 - s.Objective/100) * float64(n*24*60)
		fmt.Fprintf(&b, "## %s %s\n\n", f.Service, s.Name)
		fmt.Fprintf(&b, "Objective: %s%% over %s. Error budget: %s minutes of full outage, or the same amount spread as errors.\n\n", g(s.Objective), s.Window, g(float64(int(mins*10+0.5))/10))
		b.WriteString("| Alert | Severity | Fires when | Budget gone in |\n|---|---|---|---|\n")
		for _, a := range Alerts(n) {
			fmt.Fprintf(&b, "| SLOBurnRate%s%s | %s | burn rate above %sx over %s and %s | %s hours |\n",
				strings.ToUpper(a.Severity[:1])+a.Severity[1:], strings.ToUpper(a.Long), a.Severity, g(a.Rate), a.Long, a.Short, g(a.HoursToEmpty))
		}
		b.WriteString("\n### When a page fires\n\n")
		b.WriteString("1. Confirm it is real: open the error ratio over the long and short windows. Both are above the line.\n")
		b.WriteString("2. Check what changed in the last hour: deploys, config, certificates, upstream dependencies.\n")
		b.WriteString("3. If a deploy lines up with the start, roll it back first and investigate after.\n")
		b.WriteString("4. If nothing changed, find the failing dependency or the saturated resource, and shed or scale.\n")
		b.WriteString("5. Post what you see and what you tried in the incident channel every 15 minutes.\n")
		b.WriteString("6. After recovery, write down the cause, the fix and one change that stops it recurring.\n\n")
		b.WriteString("### When a ticket fires\n\n")
		b.WriteString("The budget is draining slowly. Find the cause this week. If the budget is spent, pause risky releases until it recovers.\n\n")
	}
	return b.String()
}
