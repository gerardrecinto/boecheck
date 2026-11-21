// boecheck turns Kubernetes, Helm, Terraform and Ansible files into a NIST
// SP 800-53r5 Body of Evidence, and SLO files into burn-rate rules and a runbook.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gerardrecinto/boecheck/internal/boe"
)

const usage = `boecheck: evidence for NIST 800-53r5, 800-207 and HIPAA from config files

  boecheck scan [--json] [--boe FILE] [--strict] [--skip BG007,TF005] [-v] PATH...
        PATH is a file, a directory, or - for stdin (for example: helm template . | boecheck scan -)
        exit 1 if any check fails (with --strict, if any check warns)
  boecheck slo FILE        print Prometheus burn-rate rules for an SLO file
  boecheck runbook FILE    print a Markdown runbook for the same alerts
  boecheck checks          list every check and the controls it maps to
`

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], in, out, errw)
	case "slo", "runbook":
		if len(args) != 2 {
			fmt.Fprint(errw, usage)
			return 2
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(errw, err)
			return 2
		}
		f, err := boe.ParseSLO(b)
		if err != nil {
			fmt.Fprintln(errw, "slo file:", err)
			return 2
		}
		if args[0] == "runbook" {
			fmt.Fprint(out, boe.Runbook(f))
			return 0
		}
		r, err := boe.Rules(f)
		if err != nil {
			fmt.Fprintln(errw, err)
			return 2
		}
		fmt.Fprint(out, r)
		return 0
	case "checks":
		if len(args) > 1 && args[1] == "--json" {
			e := json.NewEncoder(out)
			e.SetIndent("", "  ")
			_ = e.Encode(boe.Catalog)
			return 0
		}
		for _, c := range boe.Catalog {
			fmt.Fprintf(out, "%s  %-5s %s  [%s]\n", c.ID, c.Level, c.Title, strings.Join(c.NIST, ", "))
		}
		return 0
	}
	fmt.Fprint(errw, usage)
	return 2
}

func scan(args []string, in io.Reader, out, errw io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(errw)
	asJSON := fl.Bool("json", false, "print results as JSON")
	boeFile := fl.String("boe", "", "write the Body of Evidence Markdown to this file")
	strict := fl.Bool("strict", false, "exit 1 on warnings too")
	skip := fl.String("skip", "", "comma-separated check IDs to leave out")
	verbose := fl.Bool("v", false, "also print passing checks")
	title := fl.String("title", "", "title for the Body of Evidence")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() == 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	files, err := collect(fl.Args(), in)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintln(errw, "no .yaml, .yml or .tf files found")
		return 2
	}
	opt := boe.Options{Skip: map[string]bool{}}
	for _, s := range strings.Split(*skip, ",") {
		if s = strings.TrimSpace(s); s != "" {
			opt.Skip[s] = true
		}
	}
	rs, err := boe.Scan(files, opt)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 2
	}
	if *boeFile != "" {
		t := *title
		if t == "" {
			t = strings.Join(fl.Args(), ", ")
		}
		if err := os.WriteFile(*boeFile, []byte(boe.BoE(t, rs)), 0o644); err != nil {
			fmt.Fprintln(errw, err)
			return 2
		}
	}
	if *asJSON {
		e := json.NewEncoder(out)
		e.SetIndent("", "  ")
		_ = e.Encode(rs)
	} else {
		fmt.Fprint(out, boe.Text(rs, *verbose))
	}
	_, w, f := boe.Counts(rs)
	if f > 0 || (*strict && w > 0) {
		return 1
	}
	return 0
}

func collect(paths []string, in io.Reader) ([]boe.File, error) {
	var files []boe.File
	for _, p := range paths {
		if p == "-" {
			b, err := io.ReadAll(in)
			if err != nil {
				return nil, err
			}
			name := "stdin.yaml"
			if strings.Contains(string(b), "resource \"") {
				name = "stdin.tf"
			}
			files = append(files, boe.File{Name: name, Data: b})
			continue
		}
		err := filepath.WalkDir(p, func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(name)) {
			case ".yaml", ".yml", ".tf":
				b, e := os.ReadFile(name)
				if e != nil {
					return e
				}
				files = append(files, boe.File{Name: filepath.ToSlash(name), Data: b})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
