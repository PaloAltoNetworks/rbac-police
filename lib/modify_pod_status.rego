package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can modify pods' status may match a pod's labels to services' selectors in order to intercept connections to services in the pod's namespace"
  severity := "Low"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, owner) {
  not pb.blockedByNodeRestrictionV117(owner)
  rule := roles[_].rules[_]
  pb.subresourceOrWildcard(rule.resources, "pods/status")
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
} 
