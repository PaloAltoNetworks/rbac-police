package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can update and patch pods in privileged namespaces (%v) can gain code execution on pods that are likey to be privileged", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]

  pb.valueOrWildcard(rule.apiGroups, "")
  pb.valueOrWildcard(rule.resources, "pods")
  pb.updateOrPatchOrWildcard(rule.verbs) 
  not pb.hasKey(rule, "resourceNames")
} 
