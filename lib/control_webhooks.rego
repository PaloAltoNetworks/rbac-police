package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can create, update or patch ValidatingWebhookConfigurations or MutatingWebhookConfigurations can read, and in the case of the latter also mutate, any object admitted to the cluster"
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  rule := roles[_].rules[_]
  validatingwebhookOrMutatingwebhook(rule.resources)
  pb.createUpdatePatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "admissionregistration.k8s.io")
} 

validatingwebhookOrMutatingwebhook(resources) {
  "validatingwebhookconfigurations" in resources
} { 
  "mutatingwebhookconfigurations" in resources
} {
  pb.hasWildcard(resources)
}
