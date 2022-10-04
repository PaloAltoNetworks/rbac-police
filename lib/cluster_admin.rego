package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities with cluster admin privileges pose a significant threat to the cluster if compromised"
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.hasWildcard(rule.verbs)
  pb.hasWildcard(rule.resources)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
