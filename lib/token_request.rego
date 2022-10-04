package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can create TokenRequests (serviceaccounts/token) in privileged namespaces (%v) can issue tokens for admin-equivalent SAs", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  pb.subresourceOrWildcard(rule.resources, "serviceaccounts/token")
  pb.valueOrWildcard(rule.verbs, "create")
  pb.valueOrWildcard(rule.apiGroups, "")
} 
