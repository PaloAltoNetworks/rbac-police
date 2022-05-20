package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can bind clusterrolebindings or bind rolebindings in privileged namespaces (%v) can grant admin-equivalent permissions to themselves", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  rolebindingsOrClusterrolebindings(rule.resources)
  pb.valueOrWildcard(rule.verbs, "bind")
  pb.valueOrWildcard(rule.apiGroups, "rbac.authorization.k8s.io")
} 

rolebindingsOrClusterrolebindings(resources) {
  resources[_] == "clusterrolebindings"
} {
  resources[_] == "rolebindings" 
} {
  pb.hasWildcard(resources)
}
