# rbac-police <img src="./docs/logo.png" width="50">
Retrieve the RBAC permissions of Kubernetes identities - service accounts, pods, nodes, users and groups - and evaluate them using policies written in Rego.

![example](docs/example.png)

The [policy library](./lib) includes ~20 policies that identify identities possessing risky permissions, each detecting a different attack path. See the Recommendations section [here](https://www.paloaltonetworks.com/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms) for advice on addressing powerful permissions in Kubernetes clusters.

## Quick Start

1. Clone the repository:

    ```shell
    git clone https://github.com/PaloAltoNetworks/rbac-police && cd rbac-police
    ```
2. Either install `rbac-police` from a release:

    ```shell
    OS=linux  # OS=darwin
    ARCH=amd64  # ARCH=arm64
    LATEST_TAG=$(curl -s https://api.github.com/repos/PaloAltoNetworks/rbac-police/releases/latest | jq -r '.tag_name')
    curl -L -o rbac-police "https://github.com/PaloAltoNetworks/rbac-police/releases/download/${LATEST_TAG}/rbac-police_${LATEST_TAG}_${OS}_${ARCH}" && chmod +x rbac-police
    ```
    Or build it with [Golang](https://go.dev/doc/install)>=1.16:
    
    ```shell
    go build
    ```
3. Connect `kubectl` to a Kubernetes cluster.
4. Evaluate RBAC permissions and identify privilege escalation paths in your cluster using the default policy library:

    ```
    ./rbac-police eval lib/
    ```

## Usage
### Set severity threshold
Only evaluate policies with a severity equal to or higher than a threshold.
```
./rbac-police eval lib/ -s High
```
### Configure violation types
Configure which identities are evaluated for violations, default are `sa,node,combined`.
```
./rbac-police eval lib/ --violations sa,user
./rbac-police eval lib/ --violations all  # sa,node,combined,user,group
```
Note that by default, `rbac-police` only considers service accounts that are assigned to a pod. Use `-a` to include all service accounts.
### Scope to a namespace
Only look into service accounts and pods from a certain namespace.
```
./rbac-police eval lib/ -n production
```
### Only alert on SAs that exist on all nodes
Only consider violations from service accounts that exist on all nodes. Useful for identifying violating DaemonSets.
```
./rbac-police eval lib/ --only-sas-on-all-nodes
```
### Discover protections
Improve accuracy by identifying security-related features gates and admission controllers that can protect against certain attacks. Please note that [NodeRestriction](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction) is identified by impersonating a node and *dry-run creating a pod*, which may be logged by some systems.
```
./rbac-police eval lib/ -w
```
### Ignore control plane
Ignore control plane pods and nodes in clusters that host the control plane.
```
./rbac-police eval lib/ --ignore-controlplane
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
### View the permissions of a specific identity
Inspect the permissions of a single identity.
```
./rbac-police expand -z sa=kube-system:metrics-server
./rbac-police expand -z user=example@email.com
```

## Documentation
 - [Policies](docs/policies.md)
 - [Eval command](docs/eval.md)
 - [Collect command](docs/collect.md)
 - [Expand command](docs/expand.md)

## Media Mentions
Radiohead:
> rbac-police, I've given all I can. It's not enough...

N.W.A:
> rbac-police comin' straight from the underground!
