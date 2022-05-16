package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can create, update or patch ValidatingWebhookConfigurations or MutatingWebhookConfigurations can read, and in the case of the latter also mutate, any object admitted to the cluster"
  severity := "High"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  rule := roles[_].rules[_]
  validatingwebhookOrMutatingwebhook(rule.resources)
  pb.createUpdatePatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "admissionregistration.k8s.io")
} 

validatingwebhookOrMutatingwebhook(resources) {
  resources[_] == "validatingwebhookconfigurations"
} { 
  resources[_] == "mutatingwebhookconfigurations"
} {
  pb.hasWildcard(resources)
}
