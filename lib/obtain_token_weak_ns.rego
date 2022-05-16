package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can obtain serviceaccount tokens in unprivileged namespaces could potentially escalate privileges"
  severity := "Low"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  not pb.affectsPrivNS(role)  # don't overlap with policy for token retrieval in privileged namespaces
  rule := role.rules[_]
  ruleCanObtainToken(rule)
} 

# This runs the retrieve_secrets, token_request, issue_token_secrets and assign_sa policies, but for unprivileged namespaces
ruleCanObtainToken(rule) {
  ruleCanAcquireToken(rule) 
  pb.valueOrWildcard(rule.apiGroups, "")
} {
  pb.ruleCanControlPodSa(rule) 
}

ruleCanAcquireToken(rule) {
  pb.valueOrWildcard(rule.resources, "secrets")
  canAbuseSecretsForToken(rule.verbs)
} {
  pb.subresourceOrWildcard(rule.resources, "serviceaccounts/token")
  pb.valueOrWildcard(rule.verbs, "create")
}

# Get - brute force token secret name (retrieve_secrets)
# List - retreive secrets (retrieve_secrets)
# Create - mannualy create a token secret (issue_token_secrets)
# Update & Patch - modfiy secret (issue_token_secrets), TODO: probably not exploitable if resourceNames is present?
canAbuseSecretsForToken(verbs) {
  verbs[_] == "list"
} { 
  verbs[_] == "get"
} {
  pb.createUpdatePatchOrWildcard(verbs)
}