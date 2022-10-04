package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can update or patch pods/ephemeralcontainers can gain code execution on other pods, and potentially break out to their node by adding an ephemeral container with a privileged securityContext"
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  rule := roles[_].rules[_]
  pb.valueOrWildcard(rule.apiGroups, "")
  pb.subresourceOrWildcard(rule.resources, "pods/ephemeralcontainers")
  pb.updateOrPatchOrWildcard(rule.verbs)
} 



