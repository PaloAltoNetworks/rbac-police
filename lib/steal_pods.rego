package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("Identities that can delete or evict pods in privileged namespaces (%v) and also make other nodes unschedulable can steal powerful pods from other nodes onto a compromised one", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "combined", "users", "groups"}

evaluateRoles(roles, owner) {
  rolesCanRemovePodsInPrivNS(roles, owner)
  rolesCanMakeNodesUnschedulable(roles, owner)
}

evaluateCombined = combinedViolations {
  combinedViolations := { combinedViolation |
    some node in input.nodes
    sasOnNode := pb.sasOnNode(node)

    # Can the node or one of its SAs remove pods?
    sasCanRemovePods := { saFullName |
      some sa in sasOnNode
      saEffectiveRoles := pb.effectiveRoles(sa.roles)
      rolesCanRemovePodsInPrivNS(saEffectiveRoles, "serviceAccount")
      saFullName := pb.saFullName(sa)
    }
    nodeCanRemovePods(node.roles, sasCanRemovePods)
    
    # Can the node or one of its SAs make other nodes unschedulable?
    sasCanMakeNodesUnschedulable := { saFullName |
      some sa in sasOnNode
      saEffectiveRoles := pb.effectiveRoles(sa.roles)
      rolesCanMakeNodesUnschedulable(saEffectiveRoles, "serviceAccount")
      saFullName := pb.saFullName(sa)
    }
    nodeCanMakeNodesUnschedulable(node.roles, sasCanMakeNodesUnschedulable)

    combinedViolation := {
      "node": node.name,
      "serviceAccounts": sasCanRemovePods | sasCanMakeNodesUnschedulable
    }
  }
}

nodeCanRemovePods(nodeRoles, sasCanRemovePods) {
  count(sasCanRemovePods) > 0
} {
  nodeEffectiveRoles := pb.effectiveRoles(nodeRoles)
  rolesCanRemovePodsInPrivNS(nodeEffectiveRoles, "node")
}

nodeCanMakeNodesUnschedulable(nodeRoles, sasCanMakeNodesUnschedulable) {
  count(sasCanMakeNodesUnschedulable) > 0
} {
  nodeEffectiveRoles := pb.effectiveRoles(nodeRoles)
  rolesCanMakeNodesUnschedulable(nodeEffectiveRoles, "node")
}

rolesCanRemovePodsInPrivNS(roles, owner) {
  some role in roles
  pb.affectsPrivNS(role)
  roleCanRemovePods(role, owner)
}

rolesCanMakeNodesUnschedulable(roles, owner) {
  not pb.nodeRestrictionEnabledAndIsNode(owner)
  rule := roles[_].rules[_]
  nodeOrNodeStatus(rule.resources)
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
}

roleCanRemovePods(role, roleOwner) {
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "")
  ruleCanRemovePods(rule, roleOwner)
}

# Permissions that would allow one to remove a pod
ruleCanRemovePods(rule, ruleOwner) {
  # Check perms that allow removal but may be blocked by NodeRestriction
  not pb.nodeRestrictionEnabledAndIsNode(ruleOwner)
  ruleCanRemovePodsInner(rule)
} {
  # Check perms that allow removal but may be blocked by NodeRestriction from v1.17
  not pb.nodeRestrictionV117EnabledAndIsNode(ruleOwner)
  pb.subresourceOrWildcard(rule.resources, "pods/status")
  pb.updateOrPatchOrWildcard(rule.verbs)
}

# update / patch pods: set a pod's labels to match a pod controller, triggering the removal of a real replica
# delete pods: simply delete a pod
# create pods/eviction: evict a pod
# delete nodes: delete a node to evict all its pods
# update nodes: taint a node with the NoExecute taint to evict its pods
ruleCanRemovePodsInner(rule) {
  pb.valueOrWildcard(rule.resources, "pods")
  pb.updateOrPatchOrWildcard(rule.verbs)
} {
  not pb.hasKey(rule, "resourceNames")
  ruleCanRemovePodsInner2(rule)
}

# These are most likely benign with resourceNames
ruleCanRemovePodsInner2(rule) {
  pb.valueOrWildcard(rule.resources, "pods")
  pb.valueOrWildcard(rule.verbs, "delete")
} {
  pb.subresourceOrWildcard(rule.resources, "pods/eviction")
  pb.valueOrWildcard(rule.verbs, "create")
} {
  pb.valueOrWildcard(rule.resources, "nodes")
  pb.valueOrWildcard(rule.verbs, "delete")
} {
  pb.valueOrWildcard(rule.resources, "nodes")
  pb.updateOrPatchOrWildcard(rule.verbs)
}

nodeOrNodeStatus(resources) {
  pb.valueOrWildcard(resources, "nodes")
} {
  pb.subresourceOrWildcard(resources, "nodes/status")
}
