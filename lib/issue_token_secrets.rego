package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can create or modify secrets in privileged namespaces (%v) can issue tokens for admin-equivalent SAs", [concat(", ", pb.privileged_namespaces)])
  severity := "Critical"
}
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  role := roles[_]
  pb.affectsPrivNS(role)
  rule := role.rules[_]
  pb.valueOrWildcard(rule.resources, "secrets")
  pb.createUpdatePatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
  # TODO: Improve accuracy, only alert when rules grant 
  # the following perm bundles over privileged namespaces (port any improvments to obtain_token_weak_ns)
  #  [*] create && get && no resource names 
  #     - Starting from ~1.26 'get' won't be enough as SA token secrets will be removed
  #     - create alone isn't enough since you cannot retreive the secret
  #     - with resource name you can't actually create the secret without having 'patch' as well
  #  [*] create && patch (server side apply)
  #  [*] update || patch && no resource names
  #     - with resource names the secret most likey already exists 
  #       and isn't of type SA token
} 
