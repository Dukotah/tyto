package engagement

// ProvisionedCredential is a credential the CLIENT supplies for the engagement
// (e.g. a test account) so tyto can perform AUTHENTICATED testing. It is scoped
// to a target; the engine feeds a matching one into the `login` tool. Secrets
// here are operator-supplied (unlike recovered credentials) but are still
// redacted in the audit trail and never reach the planner prompt.
type ProvisionedCredential struct {
	Username string `yaml:"username"`
	Secret   string `yaml:"secret"`
	Target   string `yaml:"target"`    // host or URL this credential is for
	LoginURL string `yaml:"login_url"` // form endpoint (form mode); optional
	Mode     string `yaml:"mode"`      // "form" (default) | "basic"
}

// ProvisionedFor returns the first provisioned credential whose Target host
// matches the given target host, or ok=false if none.
func (e *Engagement) ProvisionedFor(target string) (ProvisionedCredential, bool) {
	h := hostOf(target)
	for _, c := range e.ProvisionedCredentials {
		if hostOf(c.Target) == h || c.Target == target {
			return c, true
		}
	}
	return ProvisionedCredential{}, false
}
