package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "SAs and nodes that can create and approve certificatesigningrequests can issue arbitrary certificates with cluster admin privileges"
  severity := "Critical" 
}
checkCombined := true
checkServiceAccounts := true
checkNodes := true

# https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/
# To create a CSR 
#   1. Verbs: create, get, list, watch, group: certificates.k8s.io, resource: certificatesigningrequests
# To approve a CSR 
#   2. Verbs: get, list, watch, group: certificates.k8s.io, resource: certificatesigningrequests
#   3. Verbs: update, group: certificates.k8s.io, resource: certificatesigningrequests/approval
#   4. Verbs: approve, group: certificates.k8s.io, resource: signers, resourceName: <signerNameDomain>/<signerNamePath> or <signerNameDomain>/*
# Nodes already have the 1 & 2: https://github.com/kubernetes/kubernetes/blob/e847b849c4d170b872d6020bfc2263d02c05e369/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go#L150

evaluateRoles(roles, type) {
  rolesCanUpdateCsrsApproval(roles)
  rolesCanApproveSigners(roles)
  rolesCanCreateAndRetrieveCsrs(roles, type)
}

rolesCanCreateAndRetrieveCsrs(roles, type) {
  type == "node"
} {
  rolesCanRetrieveCsrs(roles)
  rolesCanCreateCsrs(roles)
}

evaluateCombined = combinedViolations {
  combinedViolations := { combinedViolation |
    some node in input.nodes
    sasOnNode := pb.sasOnNode(node)

    # Can the node or one of its SAs update CSR approvals?
    sasCanUpdateCsrApproval := { saFullName | 
      some sa in sasOnNode
      saEffectiveRoles := pb.effectiveRoles(sa.roles)
      rolesCanUpdateCsrsApproval(saEffectiveRoles)
      saFullName := pb.saFullName(sa)
    }
    nodeCanUpdateCsrsApproval(node.roles, sasCanUpdateCsrApproval)

    # Can the node or one of its SAs approve signers?
    sasCanApproveSigners := { saFullName | 
      some sa in sasOnNode 
      saEffectiveRoles := pb.effectiveRoles(sa.roles)
      rolesCanApproveSigners(saEffectiveRoles)
      saFullName := pb.saFullName(sa)
    }
    nodeCanApproveSigners(node.roles, sasCanApproveSigners)
    
    combinedViolation := {
      "node": node.name,
      "serviceAccounts": sasCanUpdateCsrApproval | sasCanApproveSigners
    }
  }
}


nodeCanUpdateCsrsApproval(nodeRoles, sasCanUpdateCsrApproval) {
  count(sasCanUpdateCsrApproval) > 0
} {
  nodeEffectiveRoles := pb.effectiveRoles(nodeRoles)
  rolesCanUpdateCsrsApproval(nodeEffectiveRoles)
}

nodeCanApproveSigners(nodeRoles, sasCanApproveSigners) {
  count(sasCanApproveSigners) > 0
} {
  nodeEffectiveRoles := pb.effectiveRoles(nodeRoles)
  rolesCanApproveSigners(nodeEffectiveRoles)
}

rolesCanUpdateCsrsApproval(roles) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "certificates.k8s.io")
  pb.updateOrPatchOrWildcard(rule.verbs) # https://github.com/kubernetes/kubernetes/blob/442a69c3bdf6fe8e525b05887e57d89db1e2f3a5/plugin/pkg/admission/certificates/approval/admission.go#L77
  pb.subresourceOrWildcard(rule.resources, "certificatesigningrequests/approval")
}

rolesCanApproveSigners(roles) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "certificates.k8s.io")
  pb.valueOrWildcard(rule.verbs, "approve")
  pb.valueOrWildcard(rule.resources, "signers")
}

rolesCanCreateCsrs(roles) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "certificates.k8s.io")
  pb.valueOrWildcard(rule.verbs, "create")
}

rolesCanRetrieveCsrs(roles) {
  some role in roles
  pb.notNamespaced(role)
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "certificates.k8s.io")
  getListWatchOrWildcard(rule.verbs) 
}

getListWatchOrWildcard(verbs) {
  pb.getOrListOrWildcard(verbs)
} {
  "watch" in verbs
}