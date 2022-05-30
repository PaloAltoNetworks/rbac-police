package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes with cluster admin privileges pose a significant threat to the cluster if compromised"
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.hasWildcard(rule.verbs)
  pb.hasWildcard(rule.resources)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
