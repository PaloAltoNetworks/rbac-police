package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can bind clusterrolebindings or bind rolebindings in privileged namespaces (%v) can grant admin-equivalent permissions to themselves", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  rolebindingsOrClusterrolebindings(rule.resources)
  pb.valueOrWildcard(rule.verbs, "bind")
  pb.valueOrWildcard(rule.apiGroups, "rbac.authorization.k8s.io")
} 

rolebindingsOrClusterrolebindings(resources) {
  "clusterrolebindings" in resources
} {
  "rolebindings" in resources
} {
  pb.hasWildcard(resources)
}
