# rbac-police <img src="./docs/logo.png" width="50">
Retrieve the RBAC permissions of serviceAccounts, pods and nodes in a Kubernetes cluster, and evaluate them using policies written in Rego.

The [default policy library](./lib) includes around 20 policies that identify serviceAccounts, pods and nodes that possess risky permissions, each detecting a different attack path. See the Recommendations section [here](https://www.paloaltonetworks.com/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms) for advice on addressing powerful permissions in Kubernetes clusters.


## Quick Start
Requires [Golang](https://go.dev/doc/install)>=1.16.

1. Build `rbac-police`
```shell
go build
```
2. Connect `kubectl` to a Kubernetes cluster.
3. Evaluate RBAC permissions and identify privilege escalation paths in your cluster using the default policy library.
```shell
./rbac-police eval lib/
```

## Use Cases
Evaluate RBAC permissions and identify privilege escalation paths in your cluster.
```
./rbac-police eval lib/
```
### Set severity threshold
Only evaluate policies with a severity equal to or higher than a threshold.
```
./rbac-police eval lib/ -s High
```
### Scope to a namespace
Collect and evaluate RBAC permssions in a certain namespace.
```
./rbac-police eval lib/ -n production
```
### Only alert on SAs that exist on all nodes
Only consider violations from service accounts that exist on all nodes. Useful for identifying violating DaemonSets.
```
./rbac-police eval lib/ --only-sas-on-all-nodes
```
###  Ignore control plane
Ignore control plane pods and nodes in clusters that host the control plane.
```
./rbac-police eval lib/ --ignore-controlplane
```
### Nodes don't use NodeAuthorizer
Specify a custom user used by nodes in clusters that don't use the NodeAuthorizer.
```
./rbac-police eval lib/ --node-user=nodeclient
```
### Collect once for multiple evaluations
```
./rbac-police collect -o rbacDb.json
./rbac-police eval lib/ rbacDb.json -s Critical
./rbac-police eval lib/ rbacDb.json --only-sas-on-all-nodes
```
### Manually inspect RBAC permissions
```
./rbac-police expand
```
Or:
```
./rbac-police collect -o rbacDb.json
./rbac-police expand rbacDb.json
```

## Documentation
 - [Policies](docs/policies.md)
 - [Eval command](docs/eval.md)
 - [Collect command](docs/collect.md)
 - [Expand command](docs/expand.md)

## Help
```
Usage:
  rbac-police [command]

Available Commands:
  collect     Collects the RBAC permissions of serviceAccounts, pods and nodes
  completion  Generate the autocompletion script for the specified shell
  eval        Evaulates RBAC permissions of serviceAccounts, pods and nodes using Rego policies
  expand      Presents the RBAC permissions of serviceAccounts, pods and nodes in a human-readable format
  help        Help about any command

Flags:
  -a, --all-serviceaccounts   collect data on all serviceAccounts, not only those assigned to a pod
  -h, --help                  help for rbac-police
      --ignore-controlplane   don't collect data on control plane nodes and pods. Identified by either the 'node-role.kubernetes.io/control-plane' or 'node-role.kubernetes.io/master' labels. ServiceAccounts will not be linked to control plane components
  -l, --loud                  loud mode, print results regardless of -o
  -n, --namespace string      scope collection on serviceAccounts to a namespace
      --node-groups strings   treat nodes as part of these groups (default [system:nodes])
      --node-user string      user assigned to all nodes, default behaviour assumes nodes users are compatible with the NodeAuthorizer
  -o, --out-file string       save results to file

Use "rbac-police [command] --help" for more information about a command.
```

## Media Mentions
Radiohead:
> rbac-police, I've given all I can. It's not enough...

N.W.A:
> rbac-police comin' straight from the underground!
