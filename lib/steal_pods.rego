package policy
import data.police_builtins as pb
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can delete or evict pods in privileged namespaces (%v) and also make other nodes unschedulable can steal powerful pods from other nodes onto a compromised one", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
checkCombined := true
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  rolesCanRemovePodsInPrivNS(roles)
  rolesCanMakeNodesUnschedulable(roles)
}

evaluateCombined = combinedViolations {
  combinedViolations := { combinedViolation |
    some node in input.nodes
    sasOnNode := pb.sasOnNode(node)

    # Can the node or one of its SAs remove pods?
    sasCanRemovePods := { saFullName |
      some sa in sasOnNode
      saEffectiveRoles := pb.effectiveRoles(sa.roles)
      rolesCanRemovePodsInPrivNS(saEffectiveRoles)
      saFullName := pb.saFullName(sa)
    }
    nodeCanRemovePods(node.roles, sasCanRemovePods)
    
    # Can the node or one of its SAs make other nodes unschedulable?
    sasCanMakeNodesUnschedulable := { saFullName |
      some sa in sasOnNode
      saEffectiveRoles := pb.effectiveRoles(sa.roles)
      rolesCanMakeNodesUnschedulable(saEffectiveRoles)
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
  rolesCanRemovePodsInPrivNS(nodeEffectiveRoles)
}

nodeCanMakeNodesUnschedulable(nodeRoles, sasCanMakeNodesUnschedulable) {
  count(sasCanMakeNodesUnschedulable) > 0
} {
  nodeEffectiveRoles := pb.effectiveRoles(nodeRoles)
  rolesCanMakeNodesUnschedulable(nodeEffectiveRoles)
}

rolesCanRemovePodsInPrivNS(roles) {
  some role in roles
  pb.affectsPrivNS(role)
  roleCanRemovePods(role)
}

rolesCanMakeNodesUnschedulable(roles) {
  rule := roles[_].rules[_]
  nodeOrNodeStatus(rule.resources)
  pb.updateOrPatchOrWildcard(rule.verbs)
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
}

roleCanRemovePods(role) {
  some rule in role.rules
  pb.valueOrWildcard(rule.apiGroups, "")
  not pb.hasKey(rule, "resourceNames")
  ruleCanRemovePods(rule)
}

ruleCanRemovePods(rule){
  pb.valueOrWildcard(rule.resources, "pods")
  pb.valueOrWildcard(rule.verbs, "delete")
} {
  pb.subresourceOrWildcard(rule.resources, "pods/eviction")
  pb.valueOrWildcard(rule.verbs, "create")
} {
  podOrPodStatus(rule.resources)
  pb.updateOrPatchOrWildcard(rule.verbs)
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

podOrPodStatus(resources) {
  pb.valueOrWildcard(resources, "pods")
} {
  pb.subresourceOrWildcard(resources, "pods/status")
}