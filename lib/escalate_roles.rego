package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can escalate clusterrole or roles in privileged namespaces (%v) are allowed to escalate privileges", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  rolesOrClusterroles(rule.resources)
  pb.valueOrWildcard(rule.verbs, "escalate")
  pb.valueOrWildcard(rule.apiGroups, "rbac.authorization.k8s.io")
}

rolesOrClusterroles(resources) {
  "clusterroles" in resources
} { 
  "roles" in resources
} {
  pb.hasWildcard(resources)
}
