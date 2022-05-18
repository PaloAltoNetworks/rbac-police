package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can create pods or create, update or patch pod controllers (e.g. DaemonSets, Deployments, Jobs) in the privileged namespaces (%v), may assign admin-equivalent SA to a pod in their control", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  pb.ruleCanControlPodSa(rule)
} 
