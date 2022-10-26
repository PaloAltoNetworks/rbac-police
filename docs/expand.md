# rbac-police expand
Presents the RBAC permissions of Kubernetes identities in a (more) human-readable format at the expense of storage. Each identity is listed alongside its permissions.

## Help
```
Usage:
  rbac-police expand [rbac-json] [flags]

Flags:
  -h, --help   help for expand
  -z, --zoom string   only show the permissions of the specified identity, format is 'type=identity', e.g. 'sa=kube-system:default', 'user=example@email.com'

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
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect", // omitempty
                    "rules": [] // k8s rule format   
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
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect", // omitempty
                    "rules": [] // k8s rule format   
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
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect", // omitempty
                    "rules": [] // k8s rule format   
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
                    "effectiveNamespace": "if granted by a roleBinding, namespace where permissions are in effect", // omitempty
                    "rules": [] // k8s rule format   
                }
            ]
        }
    ],
}
```
