package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can modify nodes' status can set or remove labels to affect scheduling constraints enforced via nodeAffinity or nodeSelectors"
  severity := "Low"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, owner) {
  not pb.blockedByNodeRestriction(owner)
  rule := roles[_].rules[_]
  pb.subresourceOrWildcard(rule.resources, "nodes/status")
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
