package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can impersonate users, groups or other serviceaccounts can escalate privileges by abusing the permissions of the impersonated identity"
  severity := "Critical"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  rule := roles[_].rules[_]
  pb.valueOrWildcard(rule.verbs, "impersonate")
  impersonationResources(rule.apiGroups, rule.resources)
} 

impersonationResources(apiGroups, resources) {
  pb.valueOrWildcard(apiGroups, "")
  usersGroupsSasOrWildcard(resources)
} {
  pb.valueOrWildcard(apiGroups, "authentication.k8s.io")
  pb.valueOrWildcard(resources, "userextras")
}

usersGroupsSasOrWildcard(resources) {
  "users" in resources
} {
  "groups" in resources
} {
  "serviceaccounts" in resources
} {
  pb.hasWildcard(resources)
}
