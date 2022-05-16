# rbac-police collect
Collects the RBAC permissions of serviceAccounts, pods and nodes. For clusters hosted on EKS and GKE, the `collect` command also identifies serviceaccount annotations that assign cloud provider IAM entities to Kubernetes serviceaccounts.

## Help
```
Usage:
  rbac-police collect [flags]

Flags:
  -h, --help   help for collect

Global Flags:
  -a, --all-serviceaccounts   collect data on all serviceAccounts, not only those assigned to a pod
      --ignore-controlplane   don't collect data on control plane nodes and pods. Identified by either the 'node-role.kubernetes.io/control-plane' or 'node-role.kubernetes.io/master' labels. ServiceAccounts will not be linked to control plane components
  -l, --loud                  loud mode, print results regardless of -o
  -n, --namespace string      scope collection on serviceAccounts to a namespace
      --node-groups strings   treat nodes as part of these groups (default [system:nodes])
      --node-user string      user assigned to all nodes, default behaviour assumes nodes users are compatible with the NodeAuthorizer
  -o, --out-file string       save results to file
```


## Output Schema
```json
{
    "metadata": {
        "cluster": "cluster name from the current kubectl context",
        "platform": "eks, gke or empty",
        "version": "cluster Kubernetes version"
    },
    "serviceAccounts": [
        {
            "name": "serviceaccount name",
            "namespace": "serviceaccount namespace",
            "nodes": [
                {
                    "name": "the node hosting the following pods",
                    "pods": [
                        "a pod assigned the service account"
                        "a pod assigned the service account"
                    ]
                },
                {
                    "name": "the node hosting the following pods",
                    "pods": [
                        "a pod assigned the service account"
                    ]
                }
            ],
            "providerIAM": { // omitempty
                "aws": "AWS role granted to this serviceaccount via the 'eks.amazonaws.com/role-arn' annotation, if exists",
                "gcp": "GCP service account binded to this serviceaccount via the 'iam.gke.io/gcp-service-account' annotation, if exists"
            },    
            "roles": [
                {
                    "name": "a role / clusterRole assigned to this serviceAccount",
                    "namespace": "role's namespace", // omitempty
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect" // omitempty
                },
            ]
        },
    ],
    "nodes": [
        {
            "name": "node name",
            "roles": [
                {
                    "name": "a role / clusterRole assigned to this node",
                    "namespace": "role's namespace", // omitempty
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect" // omitempty
                },
            ],
            "serviceAccounts": [
                "serviceAccounts hosted on this node",
                "format is namespace:name",
                "kube-system:kube-dns",
            ]
        },
    ],
    "roles": [
        {
            "name": "role or clusterrole referenced by an SA or node",
            "namespace": "role's namespace", // omitempty
            "rules": [] // k8s rule format   
        },
    ]     
}
```
