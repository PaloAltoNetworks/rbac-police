package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can modify nodes' status can set or remove labels to affect scheduling constraints enforced via nodeAffinity or nodeSelectors"
  severity := "Low"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  rule := roles[_].rules[_]
  pb.subresourceOrWildcard(rule.resources, "nodes/status")
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
