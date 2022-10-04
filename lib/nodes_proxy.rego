package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities with access to the nodes/proxy subresource can execute code on pods via the Kubelet API"
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  rule := roles[_].rules[_]
  pb.valueOrWildcard(rule.verbs, "create")
  pb.subresourceOrWildcard(rule.resources, "nodes/proxy")
  pb.valueOrWildcard(rule.apiGroups, "")
} 
