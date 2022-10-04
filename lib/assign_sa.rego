package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can create pods or create, update or patch pod controllers (e.g. DaemonSets, Deployments, Jobs) in privileged namespaces (%v), may assign an admin-equivalent SA to a pod in their control", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  some role in roles
  pb.affectsPrivNS(role)
  some rule in role.rules
  pb.ruleCanControlPodSa(rule, owner)
} 
