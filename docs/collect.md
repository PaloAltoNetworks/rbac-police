# rbac-police collect
Collects the RBAC permissions of Kubernetes identities. For clusters hosted on EKS and GKE, the `collect` command also identifies service account annotations that assign cloud provider IAM entities to Kubernetes service accounts.

## Help
```
Usage:
  rbac-police collect [flags]

Flags:
  -h, --help   help for collect

Global Flags:
  -a, --all-serviceaccounts    collect data on all serviceAccounts, not only those assigned to a pod
  -w, --discover-protections   discover features gates and admission controllers that protect against certain attacks, partly by emulating the attacks via impersonation & dry-run write operations
      --ignore-controlplane    don't collect data on control plane nodes and pods. Identified by either the 'node-role.kubernetes.io/control-plane' or 'node-role.kubernetes.io/master' labels. ServiceAccounts will not be linked to control plane components
  -j, --json-indent uint       json indent, 0 means compact mode (default 4)
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
    "metadata": {
        "cluster": "cluster name from the current kubectl context",
        "platform": "eks, gke or empty",
        "version": {
            "major": "1",
            "minor": "22",
            "gitVersion": "v1.22.10-gke.600"
        },
        "features": [
            "list of relevant feature gates and admission controllers,",
            "currently supports:",
            "LegacyTokenSecretsReducted",
            "NodeRestriction",
            "NodeRestriction1.17",
        ]
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
    "users": [
        {
            "name": "user-name",
            "roles": [
                {
                    "name": "a role / clusterRole assigned to this user",
                    "namespace": "role's namespace", // omitempty
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect" // omitempty
                }
            ]
        }
    ],
    "groups": [
        {
            "name": "group-name",
            "roles": [
                {
                    "name": "a role / clusterRole assigned to this group",
                    "namespace": "role's namespace", // omitempty
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect" // omitempty
                }
            ]
        }
    ],
    "roles": [
        {
            "name": "role or clusterrole referenced by an identity (SA, node, user or group)",
            "namespace": "role's namespace", // omitempty
            "rules": [] // k8s rule format   
        },
    ]     
}
```
