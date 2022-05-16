package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can escalate clusterrole or roles in privileged namespaces (%v) are allowed to escalate privileges", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  rolesOrClusterroles(rule.resources)
  pb.valueOrWildcard(rule.verbs, "escalate")
  pb.valueOrWildcard(rule.apiGroups, "rbac.authorization.k8s.io")
}

rolesOrClusterroles(resources) {
  resources[_] == "clusterroles"
} { 
  resources[_] == "roles"
} {
  pb.hasWildcard(resources)
}