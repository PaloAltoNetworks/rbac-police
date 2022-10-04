package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can update or patch pods in privileged namespaces (%v) can gain code execution on pods that are likely to be powerful", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "")
  pb.valueOrWildcard(rule.resources, "pods")
  pb.updateOrPatchOrWildcard(rule.verbs) 
  not pb.hasKey(rule, "resourceNames")
} 
