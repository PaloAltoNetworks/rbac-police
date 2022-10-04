package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can list secrets cluster-wide may access confidential information, and in some cases serviceAccount tokens"
  severity := "Medium"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.resources, "secrets")
  pb.valueOrWildcard(rule.verbs, "list")
  pb.valueOrWildcard(rule.apiGroups, "")
} 
