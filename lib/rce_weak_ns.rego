package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can update or patch pods or create pods/exec in unprivileged namespaces can execute code on existing pods"
  severity := "Medium"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

# This runs modify_pods and pods_exec but for weak namespaces
evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  some role in roles
  not pb.affectsPrivNS(role)
  some rule in role.rules
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
