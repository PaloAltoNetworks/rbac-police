package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes with cluster admin privileges pose a significant threat to the cluster if compromised"
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.notNamespaced(role)
  rule := role.rules[_]
  pb.hasWildcard(rule.verbs)
  pb.hasWildcard(rule.resources)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
