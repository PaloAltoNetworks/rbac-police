package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can update or patch pods or create pods/exec in unprivileged namespaces can execute code on existing pods"
  severity := "Medium"
}
checkServiceAccounts := true
checkNodes := true

# This runs modify_pods_kubesystem and pods_exec but for weak namespaces
evaluateRoles(roles, type) {
  role := roles[_]
  not pb.affectsPrivNS(role)
  rule := role.rules[_]
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
  ruleCanRCE(rule)
} 

ruleCanRCE(rule) {
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.resources, "pods")
} {
  pb.valueOrWildcard(rule.verbs, "create")
  pb.subresourceOrWildcard(rule.resources, "pods/exec")
}
