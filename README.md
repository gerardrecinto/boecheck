# boecheck

Config files in, Body of Evidence out. boecheck scans Kubernetes, Helm, Terraform and Ansible files, reports what breaks a control, and writes the evidence control by control with the file and line. It also turns an SLO file into Prometheus burn-rate alerts and a runbook.

Try it in the browser: https://gerardrecinto.github.io/boecheck/

## Run it

```bash
git clone https://github.com/gerardrecinto/boecheck.git && cd boecheck
go run ./cmd/boecheck scan examples/bad                 # 15 fail, 5 warn, exit 1
go run ./cmd/boecheck scan examples/good                # 20 pass, exit 0
go run ./cmd/boecheck scan --boe boe.md examples/bad    # also write the Body of Evidence
helm template shop examples/chart | go run ./cmd/boecheck scan -   # scan rendered Helm output
go run ./cmd/boecheck slo examples/slo.yaml             # Prometheus rules
go run ./cmd/boecheck runbook examples/slo.yaml         # RUNBOOK.md text
go run ./cmd/boecheck checks                            # every check and its controls
```

Needs Go 1.23. Exit codes: 0 clean, 1 a check failed (with `--strict`, a check warned), 2 bad input.

## What it checks

Each check maps to NIST SP 800-53r5 controls, and where it fits to NIST SP 800-207 tenets and HIPAA Security Rule sections.

| ID | Checks | 800-53r5 |
|---|---|---|
| BG001 | Non-root containers, no privilege escalation | AC-6, CM-7 |
| BG002 | Images pinned, not latest | CM-2, SI-7 |
| BG003 | CPU and memory limits | SC-5 |
| BG004 | Readiness probe | CP-10 |
| BG005 | Read-only root filesystem | CM-7, SI-7 |
| BG006 | No literal secrets in manifests | IA-5, SC-28 |
| BG007 | Default-deny NetworkPolicy per namespace | SC-7, AC-4 |
| BG008 | Istio PeerAuthentication STRICT | SC-8, SC-23 |
| BG009 | Istio AuthorizationPolicy, not allow-all | AC-3, AC-4 |
| BG010 | Dedicated service account | AC-6, AC-2 |
| BG011 | 2 or more replicas | CP-10, SC-5 |
| BG012 | Vault agent injection (evidence only) | IA-5, SC-28 |
| TF001 | No world-open ingress except 443 | SC-7 |
| TF002 | S3 default encryption | SC-28 |
| TF003 | S3 public access block | AC-3, SC-7 |
| TF004 | Encrypted database storage | SC-28 |
| TF005 | Log group retention | AU-11 |
| TF006 | Encrypted EBS volume | SC-28 |
| AN001 | Ansible TLS validation on | SC-8, SC-23 |
| AN002 | Ansible credentials vaulted | IA-5 |

Passing checks are evidence too: the Body of Evidence lists them next to the failures, with the file and line.

## SLOs

```yaml
service: checkout
slos:
  - name: availability
    objective: 99.9
    window: 30d
    errors: sum(rate(http_requests_total{job="checkout",code=~"5.."}[$WINDOW]))
    total: sum(rate(http_requests_total{job="checkout"}[$WINDOW]))
```

`boecheck slo` writes recording rules for the error ratio and three multi-window burn-rate alerts. The burn rate is the share of budget spent times the window hours, divided by the look-back hours. Over 30 days that is 14.4x for 2% in 1 hour, 6x for 5% in 6 hours, and 1x for 10% in 3 days. Each alert needs the long and the short window to agree, so a recovered incident stops paging.

## Proof

`bash scripts/e2e.sh` runs the Go tests, scans the good and bad examples, scans a rendered Helm chart through stdin, and has promtool (in Docker) check the generated rules and run a unit test: a 2% error rate fires the page alert, a 0.05% rate does not. CI runs the same script.

## Limits

- It reads files. It shows configuration, not how a system runs, and it is not an assessment. An assessor decides what counts as evidence.
- The check-to-control mapping is my reading, not an official crosswalk.
- The Terraform scanner finds resource blocks and checks their text. It does not evaluate variables, modules or `count`, so it can miss things and can be fooled.
- Ansible checks apply to plays that have `hosts` or `tasks`.
- Istio and Vault are checked as config. No mesh or Vault server is started here.
- It covers a small set of controls, not a full baseline.

MIT license.
