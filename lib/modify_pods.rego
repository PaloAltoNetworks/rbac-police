package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can update or patch pods in privileged namespaces (%v) can gain code execution on pods that are likely to be powerful", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, owner) {
  not pb.blockedByNodeRestriction(owner)
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "")
  pb.valueOrWildcard(rule.resources, "pods")
  pb.updateOrPatchOrWildcard(rule.verbs) 
  not pb.hasKey(rule, "resourceNames")
} 
