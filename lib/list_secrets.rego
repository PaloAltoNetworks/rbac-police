package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can list secrets cluster-wide may access confidential information, and in some cases serviceAccount tokens"
  severity := "Low"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, owner) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.resources, "secrets")
  pb.valueOrWildcard(rule.verbs, "list")
  pb.valueOrWildcard(rule.apiGroups, "")
} 
