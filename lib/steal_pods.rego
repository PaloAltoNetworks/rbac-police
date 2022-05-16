package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := sprintf("SAs and nodes that can delete or evict a pod in privileged namespaces (%v) and make other nodes unschedulable can steal powerful pods from other nodes onto a compromised one", [concat(", ", pb.privileged_namespaces)])
  severity := "High"
}
checkCombined := true
checkServiceAccounts := true
checkNodes := true

evaluateRoles(roles, type) {
  rolesCanRemoveKubeSystemPods(roles)
  rolesCanMakeNodesUnschedulable(roles)
}

evaluateCombined = combinedViolations {
  combinedViolations := { combinedViolation |
    node := input.nodes[_]
    sasOnNode := pb.sasOnNode(node)

    # Can the node or one of its SAs remove pods?
    sasCanRemovePods := { saFullName | saEntry := sasOnNode[_]; 
      saEffectiveRoles := pb.effectiveRoles(saEntry.roles)
      rolesCanRemoveKubeSystemPods(saEffectiveRoles)
      saFullName := pb.saFullName(saEntry)
    }
    nodeCanRemovePods(node.roles, sasCanRemovePods)
    
    # Can the node or one of its SAs make other nodes unschedulable?
    sasCanMakeNodesUnschedulable := { saFullName | saEntry := sasOnNode[_]; 
      saEffectiveRoles := pb.effectiveRoles(saEntry.roles)
      rolesCanMakeNodesUnschedulable(saEffectiveRoles)
      saFullName := pb.saFullName(saEntry)
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
  rolesCanRemoveKubeSystemPods(nodeEffectiveRoles)
}

nodeCanMakeNodesUnschedulable(nodeRoles, sasCanMakeNodesUnschedulable) {
  count(sasCanMakeNodesUnschedulable) > 0
} {
  nodeEffectiveRoles := pb.effectiveRoles(nodeRoles)
  rolesCanMakeNodesUnschedulable(nodeEffectiveRoles)
}

rolesCanRemoveKubeSystemPods(roles) {
  role := roles[_]
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
  rule = role.rules[_]
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