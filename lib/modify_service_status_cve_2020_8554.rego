package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can modify services/status may set the status.loadBalancer.ingress.ip field to exploit the unfixed CVE-2020-8554 and launch MiTM attacks against the cluster. Most mitigations for CVE-2020-8554 only prevent ExternalIP services"
  severity := "Medium"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, owner) {
  rule := roles[_].rules[_]
  pb.subresourceOrWildcard(rule.resources, "services/status")
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
  # Considered adding create endpoint || update service as another requirement (control the endpoint where traffic is stolen to)
  # Dropped since an existing service may already point to a pod in the attacker's orbit, so it's not necessarily a requirement.
} 
