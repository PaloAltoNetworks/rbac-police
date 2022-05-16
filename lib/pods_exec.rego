package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes with the create pods/exec permission in privileged namespaces (%v) can execute code on pods who are likely to be powerful", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  pb.subresourceOrWildcard(rule.resources, "pods/exec")
  pb.valueOrWildcard(rule.verbs, "create")
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
} 



