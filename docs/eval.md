# rbac-police eval
Evaulates the RBAC permissions of Kubernetes identities using policies written in Rego. If a RBAC permission JSON file isn't provided as an argument, `eval` internally calls [`collect`](./collect.md).

See [policies.md](./policies.md) for the list of built-in policies and for instructions on creating new ones. The built-in policy library aim to identify privilege escaltion paths in a cluster.


## Help
```
Usage:
  rbac-police eval <policies> [rbac-json] [flags]

Flags:
  -d, --debug                        debug mode, prints debug info and stdout of policies
  -h, --help                         help for eval
      --ignored-namespaces strings   ignore serviceAccounts from certain namespaces during eval
      --only-sas-on-all-nodes        only evaluate serviceAccounts that exist on all nodes
  -s, --severity-threshold string    only evaluate policies with severity >= threshold (default "Low")
      --short                        abbreviate results
      --violations strings           violations to search for, beside default supports 'user', 'group' and 'all' (default [sa,node,combined])

Global Flags:
  -a, --all-serviceaccounts    collect data on all serviceAccounts, not only those assigned to a pod
  -w, --discover-protections   discover features gates and admission controllers that protect against certain attacks, partly by emulating the attacks via impersonation & dry-run write operations
      --ignore-controlplane    don't collect data on control plane nodes and pods. Identified by either the 'node-role.kubernetes.io/control-plane' or 'node-role.kubernetes.io/master' labels. ServiceAccounts will not be linked to control plane components
      --local-dir string       offline mode, get cluster data from local files, see <rbac-police>/utils/get_cluster_data.sh
  -l, --loud                   loud mode, print results regardless of -o
  -n, --namespace string       scope collection on serviceAccounts to a namespace
      --node-groups strings    treat nodes as part of these groups (default [system:nodes])
      --node-user string       user assigned to all nodes, default behaviour assumes nodes users are compatible with the NodeAuthorizer
  -o, --out-file string        save results to file
```

## Output Schema
```json
{
    "policyResults": [
        {
            "policy": "policy file that produced results",
            "severity": "policy's severity",
            "description": "policy's description",
            "violations": {
                "serviceAccounts": [ // omitempty
                    {
                        "name": "a serviceAccount who violated the policy",
                        "namespace": "namespace",
                        "nodes": [
                            {
                                "node-name": [
                                    "pod running on node-name assigned the violation serviceaccount",
                                    "mypod",
                                ],
                            },
                            {
                                "second-node": [
                                    "pod running on second-node assigned the violation serviceaccount",
                                    "anotherpod",
                                ],
                            }
                        ],
                        "providerIAM": { // omitempty
                            "aws": "AWS role granted to this serviceaccount via the 'eks.amazonaws.com/role-arn' annotation, if exists",
                            "gcp": "GCP service account binded to this serviceaccount via the 'iam.gke.io/gcp-service-account' annotation, if exists"
                        },    
                    },
                ],
                "nodes": [ // omitempty
                    "list of node names",
                    "that violated the policy"
                ],
                "combined": [ // omitempty
                    {
                        "node": "node that alongside the serviceAccounts below, violated the policy",
                        "serviceAccounts": [
                            "serviceAccounts which with their permissions",
                            "along with the node permissions",
                            "resulted in violation of the policy",
                            "namespace:name",
                            "default:default"
                        ]
                    },
                ],
                "users": [ // omitempty
                    "users-who-violated-the-policy",
                    "system:kube-controller-manager",
                    "john@email.com"
                ],
                "groups": [ // omitempty
                    "groups-who-violated-the-policy",
                    "system:nodes",
                    "qa-group"
                ],
            }
        },
    ]
}
```
