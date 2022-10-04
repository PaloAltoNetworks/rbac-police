package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities that can retrieve or issue SA tokens in unprivileged namespaces could potentially obtain tokens with broader permissions over the cluster"
  severity := "Low"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  some role in roles
  not pb.affectsPrivNS(role)  # don't overlap with policy for token retrieval in privileged namespaces
  some rule in role.rules
  ruleCanObtainToken(rule, owner)
} 

# This runs the retrieve_secrets, token_request, issue_token_secrets and assign_sa policies, but for unprivileged namespaces
ruleCanObtainToken(rule, ruleOwner) {
  ruleCanAcquireToken(rule, ruleOwner) 
  pb.valueOrWildcard(rule.apiGroups, "")
} {
  pb.ruleCanControlPodSa(rule, ruleOwner) 
}

ruleCanAcquireToken(rule, ruleOwner) {
  pb.valueOrWildcard(rule.resources, "secrets")
  canAbuseSecretsForToken(rule.verbs)
} {
  not pb.nodeRestrictionEnabledAndIsNode(ruleOwner)
  pb.subresourceOrWildcard(rule.resources, "serviceaccounts/token")
  pb.valueOrWildcard(rule.verbs, "create")
}

# Get - brute force token secret name (retrieve_secrets)
# List - retreive secrets (retrieve_secrets)
# Create - mannualy create a token secret (issue_token_secrets)
# Update & Patch - modfiy secret (issue_token_secrets), TODO: probably not exploitable if resourceNames is present?
canAbuseSecretsForToken(verbs) {
  not pb.legacyTokenSecretsReducted
  listOrGet(verbs)
} {
  pb.createUpdatePatchOrWildcard(verbs)
}

listOrGet(verbs) {
  "list" in verbs
} { 
  "get" in verbs
}