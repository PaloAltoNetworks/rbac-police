package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can retrieve secrets in privileged namespaces (%v) can obtain tokens of admin-equivalent SAs", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  pb.valueOrWildcard(rule.resources, "secrets")
  pb.getOrListOrWildcard(rule.verbs) # get -> bruteforcing token secrets names
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
} 


