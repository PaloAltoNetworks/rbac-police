package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can modify configmaps in the kube-system namespace on EKS clusters can obtain cluster admin privileges by overwriting the aws-auth configmap"
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  input.metadata.platform == "eks"
  role := roles[_]
  pb.notNamespacedOrNamespace(role, "kube-system")
  rule := role.rules[_]
  pb.valueOrWildcard(rule.resources, "configmaps")
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
  noResourceNamesOrValue(rule, "aws-auth")
} 

noResourceNamesOrValue(rule, value){
  not pb.hasKey(rule, "resourceNames")
} {
  rule.resourceNames[_] == value
}
