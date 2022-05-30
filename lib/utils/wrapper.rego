package wrapper

import data.policy as policy
import data.police_builtins as pb
import future.keywords.in

main[{"violations": violation}] {
  violation := {"serviceAccounts": saViolations}
} {
  violation := {"nodes": nodeViolations}
} {
  violation := {"combined": combinedViolations}
}


saViolations = violations {
  policy.checkServiceAccounts
  violations := { violation |
    some sa in input.serviceAccounts
    saEffectiveRoles := pb.effectiveRoles(sa.roles)
    policy.evaluateRoles(saEffectiveRoles, "serviceAccount")
    violation := {
      "name": sa.name,
      "namespace": sa.namespace,
      "nodes": { shortedNode | 
        some node in sa.nodes
        shortedNode := {node.name: node.pods}
      },
    }
  }
  count(violations) > 0
}

nodeViolations = violations {
  policy.checkNodes
  violations := { violation |
    some node in input.nodes
    nodeEffectiveRoles := pb.effectiveRoles(node.roles)
    policy.evaluateRoles(nodeEffectiveRoles, "node")
    violation := node.name
  }
  count(violations) > 0
}

combinedViolations = violations {
  policy.checkCombined
  violations := policy.evaluateCombined
  count(violations) > 0
}

