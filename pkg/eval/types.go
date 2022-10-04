package eval

// Configuration for Expand()
type EvalConfig struct {
	SeverityThreshold  string
	OnlySasOnAllNodes  bool
	IgnoredNamespaces  []string
	DebugMode          bool
	SaViolations       bool
	NodeViolations     bool
	CombinedViolations bool
	UserViolations     bool
	GroupViolations    bool
}

// Evalaution results for policies
type PolicyResults struct {
	PolicyResults []PolicyResult `json:"policyResults"`
	Summary       Summary        `json:"summary"`
}

// Abbreviated results for policies
type AbbreviatedPolicyResults struct {
	PolicyResults []AbbreviatedPolicyResult `json:"policyResults"`
	Summary       Summary                   `json:"summary"`
}

// Result of policy evaluation
type PolicyResult struct {
	PolicyFile  string     `json:"policy"`
	Severity    string     `json:"severity,omitempty"`
	Description string     `json:"description,omitempty"`
	Violations  Violations `json:"violations"`
}

// Result of policy evaluation, abbreviated
type AbbreviatedPolicyResult struct {
	PolicyFile  string                `json:"policy"`
	Severity    string                `json:"severity,omitempty"`
	Description string                `json:"description,omitempty"`
	Violations  AbbreviatedViolations `json:"violations,omitempty"`
}

// Summary of results from all evaluated policies
type Summary struct {
	Failed    int `json:"failed"`
	Passed    int `json:"passed"`
	Errors    int `json:"errors"`
	Evaluated int `json:"evaluated"`
}

// Policy violations
type Violations struct {
	ServiceAccounts []ServiceAccountViolation `json:"serviceAccounts,omitempty" mapstructure:"serviceAccounts"`
	Nodes           []string                  `json:"nodes,omitempty"`
	Combined        []CombinedViolation       `json:"combined,omitempty"`
	Users           []string                  `json:"users,omitempty"`
	Groups          []string                  `json:"groups,omitempty"`
}

// Policy violations, abbreviated
type AbbreviatedViolations struct {
	ServiceAccounts []string            `json:"serviceAccounts,omitempty" mapstructure:"serviceAccounts"`
	Nodes           []string            `json:"nodes,omitempty"`
	Combined        []CombinedViolation `json:"combined,omitempty"`
	Users           []string            `json:"users,omitempty"`
	Groups          []string            `json:"groups,omitempty"`
}

// Violation from a serviceAccount
type ServiceAccountViolation struct {
	Name        string                `json:"name"`
	Namespace   string                `json:"namespace"`
	Nodes       []map[string][]string `json:"nodes,omitempty"`
	ProviderIAM map[string]string     `json:"providerIAM,omitempty" mapstructure:"providerIAM"`
}

// Violation from a node and its hosted serviceAccount
type CombinedViolation struct {
	Node            string   `json:"node,omitempty"`
	ServiceAccounts []string `json:"serviceAccounts,omitempty" mapstructure:"serviceAccounts"`
}

// Output from the describe Rego rule
type DescribeRegoResult struct {
	Severity    string `json:"severity,omitempty"`
	Description string `json:"desc,omitempty" mapstructure:"desc"`
}

// Output from the main Rego rule
type EvalRegoResult struct {
	ServiceAccounts []ServiceAccountViolation `json:"serviceAccounts,omitempty" mapstructure:"serviceAccounts"`
	Nodes           []string                  `json:"nodes,omitempty"`
	Combined        []CombinedViolation       `json:"combined,omitempty"`
	Users           []string                  `json:"users,omitempty"`
	Groups          []string                  `json:"groups,omitempty"`
}

// Below severity threshold error
type belowThresholdErr struct{}

func (m *belowThresholdErr) Error() string {
	return "policy's severity is below the severity threshold"
}
