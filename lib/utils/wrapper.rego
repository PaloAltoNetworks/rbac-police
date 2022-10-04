package wrapper

import data.policy as policy
import data.police_builtins as pb
import data.config
import future.keywords.in

main[{"violations": violation}] {
  config.evalSaViolations
  violation := {"serviceAccounts": saViolations}
} {
  config.evalNodeViolations
  violation := {"nodes": nodeViolations}
} {
  config.evalCombinedViolations
  violation := {"combined": combinedViolations}
} {
  config.evalUserViolations
  violation := {"users": userViolations}
} {
  config.evalGroupViolations
  violation := {"groups": groupViolations}
}


saViolations = violations {
  "serviceAccounts" in policy.targets
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
  "nodes" in policy.targets
  violations := { violation |
    some node in input.nodes
    nodeEffectiveRoles := pb.effectiveRoles(node.roles)
    policy.evaluateRoles(nodeEffectiveRoles, "node")
    violation := node.name
  }
  count(violations) > 0
}

combinedViolations = violations {
  "combined" in policy.targets
  violations := policy.evaluateCombined
  count(violations) > 0
}

userViolations = violations {
  "users" in policy.targets
  violations := { violation |
    some user in input.users
    effectiveRoles := pb.effectiveRoles(user.roles)
    policy.evaluateRoles(effectiveRoles, "user")
    violation := user.name
  }
  count(violations) > 0
}

groupViolations = violations {
  "groups" in policy.targets
  violations := { violation |
    some group in input.groups
    effectiveRoles := pb.effectiveRoles(group.roles)
    policy.evaluateRoles(effectiveRoles, "group")
    violation := group.name
  }
  count(violations) > 0
}

