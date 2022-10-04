package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities with the create pods/exec permission in privileged namespaces (%v) can execute code on pods who are likely to be powerful", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  pb.subresourceOrWildcard(rule.resources, "pods/exec")
  pb.valueOrWildcard(rule.verbs, "create")
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
} 



