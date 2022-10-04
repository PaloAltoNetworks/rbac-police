package policy
import data.police_builtins as pb
import data.config
import future.keywords.in

describe[{"desc": desc, "severity": severity}] {
  desc := "Kubernetes ServiceAccounts assigned cloud provider IAM roles may be abused to attack the underlying cloud account (depending on the permissions of the IAM role)"
  severity := "Low"
}

main[{"violations": violation}] {
  config.evalSaViolations
  violation := {"serviceAccounts": saViolations}
} 

saViolations = violations {
  violations := { violation |
    some sa in input.serviceAccounts
    sa.providerIAM
    violation := {
      "name": sa.name,
      "namespace": sa.namespace,
      "nodes": { shortedNode | 
        some node in sa.nodes
        shortedNode := {node.name: node.pods}
      },
      "providerIAM": sa.providerIAM
    }
  }
  count(violations) > 0
}