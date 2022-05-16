package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can create TokenRequests (serviceaccounts/token) in privileged namespaces (%v) can create tokens of admin-equivalent SAs", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  pb.subresourceOrWildcard(rule.resources, "serviceaccounts/token")
  pb.valueOrWildcard(rule.verbs, "create")
  pb.valueOrWildcard(rule.apiGroups, "")
} 
