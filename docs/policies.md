# Policies
Policies are [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) scripts that detect identities like service accounts possessing RBAC permissions that match certain rule definitions. Policies produce violations, which can have 5 types:
- **ServiceAccounts**: Service accounts that violate the policy based on their permissions.
- **Nodes**: Nodes that violate the policy based on their permissions.
- **Users**: Users that violate the policy based on their permissions.
- **Groups**: Groups that violate the policy based on their permissions.
- **Combined**: Nodes that violate the policy based on the union of their permissions and those of the service account tokens they host.

The [policy library](../lib) includes ~20 policies that alert on identities possessing risky permissions, each detecting a different attack path.

## Writing Custom Policies
Policies are written in Rego, and receive input in the [schema](./collect.md#output-schema) produced by `rbac-police collect`. Policies should define a `describe` rule, at least one violation type they produce, and an evaluator. Below is the [nodes_proxy](../lib/nodes_proxy.rego) policy for example:

```rego
package policy
import data.police_builtins as pb

describe[{"desc": desc, "severity": severity}] {
  desc := "Identities with access to the nodes/proxy subresource can execute code on pods via the Kubelet API"
  severity := "High"
}
targets := {"serviceAccounts", "nodes", "users", "groups"}

evaluateRoles(roles, owner) {
  rule := roles[_].rules[_]
  pb.valueOrWildcard(rule.verbs, "create")
  pb.subresourceOrWildcard(rule.resources, "nodes/proxy")
  pb.valueOrWildcard(rule.apiGroups, "")
} 
```

- A policy must start with `package policy`.
- A policy can import a number of built-in utility functions from [builtins.rego](../lib/utils/builtins.rego) via `import data.police_builtins`.
- The `describe` rule defines the description and severity of the policy.
- The `targets` set configures which identities the policy evaluates and produces violations for.
- The `evaluateRoles` function receives the `roles` of a serviceAccount, node, user, or group, and based on them determines whether it violates the policy.
- Policies can define an `evalute_combined` rule to produce combined violations. See [approve_csrs](../lib/approve_csrs.rego) for an example.

The above options are implemented by a Rego [wrapper](../lib/utils/wrapper.rego). If full control over the execution is needed, a policy can be written to run independently, without the wrapper. See the [providerIAM](../lib/providerIAM.rego) policy for an example.

## Policy Library
### [approve_csrs](../lib/approve_csrs.rego)
- Description: `Identities that can create and approve certificatesigningrequests can issue arbitrary certificates with cluster admin privileges`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, combined, users, groups`
### [assign_sa](../lib/assign_sa.rego)
- Description: `Identities that can create pods or create, update or patch pod controllers (e.g. DaemonSets, Deployments, Jobs) in privileged namespaces, may assign an admin-equivalent SA to a pod in their control`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [bind_roles](../lib/bind_roles.rego)
- Description: `Identities that can bind clusterrolebindings or bind rolebindings in privileged namespaces can grant admin-equivalent permissions to themselves`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [cluster_admin](../lib/cluster_admin.rego)
- Description: `Identities with cluster admin privileges pose a significant threat to the cluster if compromised`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [control_webhooks](../lib/control_webhooks.rego)
- Description: `Identities that can create, update or patch ValidatingWebhookConfigurations or MutatingWebhookConfigurations can read, and in the case of the latter also mutate, any object admitted to the cluster`
- Severity: `High`
- Violation types: `serviceAccounts, nodes, users, groups`
### [eks_modify_aws_auth](../lib/eks_modify_aws_auth.rego)
- Description: `Identities that can modify configmaps in the kube-system namespace on EKS clusters can obtain cluster admin privileges by overwriting the aws-auth configmap`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [escalate_roles](../lib/escalate_roles.rego)
- Description: `Identities that can escalate clusterrole or roles in privileged namespaces are allowed to escalate privileges`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [impersonate](../lib/impersonate.rego)
- Description: `Identities that can impersonate users, groups or other serviceaccounts can escalate privileges by abusing the permissions of the impersonated identity`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [issue_token_secrets](../lib/issue_token_secrets.rego)
- Description: `Identities that can create or modify secrets in privileged namespaces can issue tokens for admin-equivalent SAs`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [list_secrets](../lib/list_secrets.rego)
- Description: `Identities that can list secrets cluster-wide may access confidential information, and in some cases serviceAccount tokens`
- Severity: `Medium`
- Violation types: `serviceAccounts, nodes, users, groups`
### [modify_node_status](../lib/modify_node_status.rego)
- Description: `Identities that can modify nodes' status can set or remove labels to affect scheduling constraints enforced via nodeAffinity or nodeSelectors`
- Severity: `Low`
- Violation types: `serviceAccounts, nodes, users, groups`
### [modify_pod_status](../lib/modify_pod_status.rego)
- Description: `Identities that can modify pods' status may match a pod's labels to services' selectors in order to intercept connections to services in the pod's namespace`
- Severity: `Low`
- Violation types: `serviceAccounts, nodes, users, groups`
### [modify_pods](../lib/modify_pods.rego)
- Description: `Identities that can update or patch pods in privileged namespaces can gain code execution on pods that are likely to be powerful`
- Severity: `High`
- Violation types: `serviceAccounts, nodes, users, groups`
### [modify_service_status_cve_2020_8554](../lib/modify_service_status_cve_2020_8554.rego)
- Description: `Identities that can modify services/status may set the status.loadBalancer.ingress.ip field to exploit the unfixed CVE-2020-8554 and launch MiTM attacks against the cluster. Most mitigations for CVE-2020-8554 only prevent ExternalIP services`
- Severity: `Medium`
- Violation types: `serviceAccounts, nodes, users, groups`
### [nodes_proxy](../lib/nodes_proxy.rego)
- Description: `Identities with access to the nodes/proxy subresource can execute code on pods via the Kubelet API`
- Severity: `High`
- Violation types: `serviceAccounts, nodes, users, groups`
### [obtain_token_weak_ns](../lib/obtain_token_weak_ns.rego)
- Description: `Identities that can retrieve or issue SA tokens in unprivileged namespaces could potentially obtain tokens with broader permissions over the cluster`
- Severity: `Low`
- Violation types: `serviceAccounts, nodes, users, groups`
### [pods_ephemeral_ctrs](../lib/pods_ephemeral_ctrs.rego)
- Description: `Identities that can update or patch pods/ephemeralcontainers can gain code execution on other pods, and potentially break out to their node by adding an ephemeral container with a privileged securityContext`
- Severity: `High`
- Violation types: `serviceAccounts, nodes, users, groups`
### [pods_exec](../lib/pods_exec.rego)
- Description: `Identities with the create pods/exec permission in privileged namespaces can execute code on pods who are likely to be powerful`
- Severity: `High`
- Violation types: `serviceAccounts, nodes, users, groups`
### [providerIAM](../lib/providerIAM.rego)
- Description: `Kubernetes ServiceAccounts assigned cloud provider IAM roles may be abused to attack the underlying cloud account (depending on the permissions of the IAM role)`
- Severity: `Low`
- Violation types: `serviceAccounts`
### [rce_weak_ns](../lib/rce_weak_ns.rego)
- Description: `Identities that can update or patch pods or create pods/exec in unprivileged namespaces can execute code on existing pods`
- Severity: `Medium`
- Violation types: `serviceAccounts, nodes, users, groups`
### [retrieve_token_secrets](../lib/retrieve_token_secrets.rego)
- Description: `Identities that can retrieve secrets in privileged namespaces can obtain tokens of admin-equivalent SAs`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
### [steal_pods](../lib/steal_pods.rego)
- Description: `Identities that can delete or evict pods in privileged namespaces and also make other nodes unschedulable can steal powerful pods from other nodes onto a compromised one`
- Severity: `High`
- Violation types: `serviceAccounts, nodes, combined, users, groups`
### [token_request](../lib/token_request.rego)
- Description: `Identities that can create TokenRequests (serviceaccounts/token) in privileged namespaces can issue tokens for admin-equivalent SAs`
- Severity: `Critical`
- Violation types: `serviceAccounts, nodes, users, groups`
