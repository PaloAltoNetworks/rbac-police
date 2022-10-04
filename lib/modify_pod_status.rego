package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can modify pods' status may match a pod's labels to services' selectors in order to intercept connections to services in the pod's namespace"
  severity := "Low"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.nodeRestrictionV117EnabledAndIsNode(owner)
  rule := roles[_].rules[_]
  pb.subresourceOrWildcard(rule.resources, "pods/status")
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
