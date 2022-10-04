package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can retrieve secrets in privileged namespaces (%v) can obtain tokens of admin-equivalent SAs", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  not pb.legacyTokenSecretsReducted
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.resources, "secrets")
  pb.getOrListOrWildcard(rule.verbs) # get -> bruteforcing token secrets names
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
} 
