package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "K8s SAs assigned cloud provider IAM roles may be abused to attack the underlying cloud account (depending on the permissions of the IAM role)"
  severity := "Low"
}

main[{"violations": violation}] {
  violation := {"serviceAccounts": saViolations}
} 

saViolations = violations {
  violations := { violation |
    sa := input.serviceAccounts[_]
    sa.providerIAM
    violation := {
      "name": sa.name,
      "namespace": sa.namespace,
      "nodes": { shortedNode | node := sa.nodes[_];
        shortedNode := {node.name: node.pods}
      },
      "providerIAM": sa.providerIAM
    }
  }
  count(violations) > 0
}