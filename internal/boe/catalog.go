package boe

// Status is the outcome of one check on one resource.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Check describes one rule and the controls it gives evidence for.
// The mapping to controls is the author's reading, not an official crosswalk.
type Check struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Level Status   `json:"level"` // Fail or Warn when the rule is violated
	NIST  []string `json:"nist80053r5"`
	ZT    []int    `json:"zeroTrustTenets,omitempty"` // NIST SP 800-207 section 2.1 tenets
	HIPAA []string `json:"hipaa,omitempty"`
	Fix   string   `json:"fix"`
}

var Catalog = []Check{
	{"BG001", "Containers run as non-root with no privilege escalation", Fail, []string{"AC-6", "CM-7"}, []int{6}, []string{"164.312(a)(1)"}, "Set runAsNonRoot: true, allowPrivilegeEscalation: false and drop privileged."},
	{"BG002", "Images are pinned, not latest", Fail, []string{"CM-2", "SI-7"}, []int{5}, []string{"164.312(c)(1)"}, "Pin the image to a digest (image@sha256:...) or at least a fixed tag."},
	{"BG003", "CPU and memory limits are set", Fail, []string{"SC-5"}, nil, []string{"164.308(a)(7)"}, "Set resources.limits.cpu and resources.limits.memory."},
	{"BG004", "Readiness probe is set", Warn, []string{"CP-10"}, nil, []string{"164.308(a)(7)"}, "Add a readinessProbe so traffic only reaches ready pods."},
	{"BG005", "Root filesystem is read-only", Warn, []string{"CM-7", "SI-7"}, nil, []string{"164.312(c)(1)"}, "Set readOnlyRootFilesystem: true and mount a volume for writable paths."},
	{"BG006", "No literal secrets in manifests", Fail, []string{"IA-5", "SC-28"}, []int{6}, []string{"164.312(a)(1)"}, "Reference a Secret with secretKeyRef, or inject from Vault. Do not commit secret values."},
	{"BG007", "Namespace has a default-deny NetworkPolicy", Fail, []string{"SC-7", "AC-4"}, []int{2}, []string{"164.312(a)(1)"}, "Add a NetworkPolicy with an empty podSelector and policyTypes: [Ingress], then allow specific flows."},
	{"BG008", "Istio PeerAuthentication is STRICT mTLS", Fail, []string{"SC-8", "SC-23"}, []int{2}, []string{"164.312(e)(1)"}, "Add a namespace-wide PeerAuthentication with mtls.mode: STRICT."},
	{"BG009", "Istio AuthorizationPolicy exists and is not allow-all", Fail, []string{"AC-3", "AC-4"}, []int{3, 6}, []string{"164.312(a)(1)"}, "Add an AuthorizationPolicy that names the allowed principals. Remove rules: [{}]."},
	{"BG010", "Workload uses its own service account", Warn, []string{"AC-6", "AC-2"}, []int{6}, nil, "Set serviceAccountName to a dedicated account, not default."},
	{"BG011", "At least 2 replicas", Warn, []string{"CP-10", "SC-5"}, nil, []string{"164.308(a)(7)"}, "Run 2 or more replicas and add a PodDisruptionBudget."},
	{"BG012", "Secrets are injected by Vault", Warn, []string{"IA-5", "SC-28"}, []int{6}, nil, "Add the vault.hashicorp.com/agent-inject annotations."},
	{"TF001", "No world-open ingress except 443", Fail, []string{"SC-7"}, []int{2}, []string{"164.312(e)(1)"}, "Restrict cidr_blocks to known ranges, or a load balancer on 443."},
	{"TF002", "S3 bucket has default encryption", Fail, []string{"SC-28"}, nil, []string{"164.312(a)(2)(iv)"}, "Add an aws_s3_bucket_server_side_encryption_configuration for the bucket."},
	{"TF003", "S3 bucket blocks public access", Fail, []string{"AC-3", "SC-7"}, nil, []string{"164.312(a)(1)"}, "Add an aws_s3_bucket_public_access_block with all four settings true."},
	{"TF004", "Database storage is encrypted", Fail, []string{"SC-28"}, nil, []string{"164.312(a)(2)(iv)"}, "Set storage_encrypted = true."},
	{"TF005", "Log group retention is set", Warn, []string{"AU-11"}, nil, []string{"164.316(b)(2)(i)"}, "Set retention_in_days to your retention requirement."},
	{"TF006", "EBS volume is encrypted", Fail, []string{"SC-28"}, nil, []string{"164.312(a)(2)(iv)"}, "Set encrypted = true."},
	{"AN001", "Playbook keeps TLS certificate validation on", Fail, []string{"SC-8", "SC-23"}, []int{2}, []string{"164.312(e)(1)"}, "Remove validate_certs: false and trust the right CA instead."},
	{"AN002", "Playbook credentials are vaulted", Fail, []string{"IA-5"}, []int{6}, []string{"164.312(a)(1)"}, "Encrypt the value with ansible-vault or read it from Vault at run time."},
}

var byID = func() map[string]Check {
	m := map[string]Check{}
	for _, c := range Catalog {
		m[c.ID] = c
	}
	return m
}()

// ControlTitles names the NIST SP 800-53r5 controls used above.
var ControlTitles = map[string]string{
	"AC-2":  "Account Management",
	"AC-3":  "Access Enforcement",
	"AC-4":  "Information Flow Enforcement",
	"AC-6":  "Least Privilege",
	"AU-11": "Audit Record Retention",
	"CM-2":  "Baseline Configuration",
	"CM-7":  "Least Functionality",
	"CP-10": "System Recovery and Reconstitution",
	"IA-5":  "Authenticator Management",
	"SC-5":  "Denial-of-Service Protection",
	"SC-7":  "Boundary Protection",
	"SC-8":  "Transmission Confidentiality and Integrity",
	"SC-23": "Session Authenticity",
	"SC-28": "Protection of Information at Rest",
	"SI-7":  "Software, Firmware, and Information Integrity",
}

// TenetTitles names the NIST SP 800-207 tenets (section 2.1).
var TenetTitles = map[int]string{
	1: "All data sources and computing services are resources",
	2: "All communication is secured regardless of network location",
	3: "Access to resources is granted per session",
	4: "Access is determined by dynamic policy",
	5: "The enterprise monitors and measures the integrity and security posture of assets",
	6: "Authentication and authorization are dynamic and strictly enforced before access",
	7: "The enterprise collects information on asset state to improve its posture",
}

// Result is one piece of evidence: a check run against one resource.
type Result struct {
	Check    string   `json:"check"`
	Title    string   `json:"title"`
	Status   Status   `json:"status"`
	NIST     []string `json:"nist80053r5"`
	ZT       []int    `json:"zeroTrustTenets,omitempty"`
	HIPAA    []string `json:"hipaa,omitempty"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Resource string   `json:"resource"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

func mk(id string, st Status, file string, line int, resource, msg string) Result {
	c := byID[id]
	r := Result{Check: id, Title: c.Title, Status: st, NIST: c.NIST, ZT: c.ZT, HIPAA: c.HIPAA,
		File: file, Line: line, Resource: resource, Message: msg}
	if st != Pass {
		r.Fix = c.Fix
	}
	return r
}

func violation(id, file string, line int, resource, msg string) Result {
	return mk(id, byID[id].Level, file, line, resource, msg)
}
