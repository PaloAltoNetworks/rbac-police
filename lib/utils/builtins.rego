package police_builtins
import future.keywords.in

privileged_namespaces := {"kube-system"}

# True if @arr contains @value or a wildcard
valueOrWildcard(arr, value) {
  value in arr
} {  
  hasWildcard(arr)
}

# True if @arr includes a wildcard
hasWildcard(arr) {
  "*" in arr
}

# True if @obj has a key @k
hasKey(obj, k) {
   _ = obj[k]
}

# True if @role isn't namespaced, or namespaced to a privileged namespace
affectsPrivNS(role) {
  notNamespaced(role)
} {
  role.effectiveNamespace in privileged_namespaces
}

# True if @role isn't namespaced, or namespaced to @ns
notNamespacedOrNamespace(role, ns) {
  notNamespaced(role)
} {
  role.effectiveNamespace == ns
}

# True if @role isn't namespaced
notNamespaced(role) {
  not hasKey(role, "effectiveNamespace")
} 

# Returns the full name of @sa
saFullName(sa) = fullName {
  fullName := sprintf("%v:%v", [sa.namespace, sa.name])
}

# True if @arr included @combinedResourceName or a wildcard that will apply to it
subresourceOrWildcard(arr, combinedResourceName) {
  combinedResourceName in arr
} { 
  subresource := split(combinedResourceName, "/")[1]
  wildcardSubresource := sprintf("*/%v", [subresource])
  wildcardSubresource in arr
} {
  hasWildcard(arr)
}

# Returns the SAs from @serviceaccounts that are hosted on the @node
sasOnNode(node) = serviceAccountsOnNode {
  serviceAccountsOnNode = { sa | 
    some sa in input.serviceAccounts
    fullname := saFullName(sa)
    fullname in node.serviceAccounts
  }
}

# True if @verbs includes either 'update', 'patch' or a wildcard
updateOrPatchOrWildcard(verbs) {
  "update" in verbs
} {
  "patch" in verbs
} { 
  hasWildcard(verbs)
} 

# True if @verbs includes either 'create', 'update', 'patch' or a wildcard
createUpdatePatchOrWildcard(verbs) {
  "create" in verbs
} {
  updateOrPatchOrWildcard(verbs)
}

# True if @verbs includes either 'get', 'list', or a wildcard
getOrListOrWildcard(verbs) {
  "list" in verbs
}{
  "get" in verbs
} {
  hasWildcard(verbs)
}

# True if by any mean, @rule is permitted to overwrite the SA of a pod
ruleCanControlPodSa(rule, ruleOwner) {
  not nodeRestrictionEnabledAndIsNode(ruleOwner)
  valueOrWildcard(rule.verbs, "create")
  valueOrWildcard(rule.resources, "pods")
  valueOrWildcard(rule.apiGroups, "")
} {
  podControllerResource(rule.resources, rule.apiGroups)
  createUpdatePatchOrWildcard(rule.verbs)
}

# True if @resources contains a resource that can control pods or a wildcard
podControllerResource(resources, apiGroups) {
  "cronjobs"in resources
  valueOrWildcard(apiGroups, "batch")
} {
  "jobs" in resources 
  valueOrWildcard(apiGroups, "batch")
} {
  "daemonsets" in resources
  valueOrWildcard(apiGroups, "apps")
} {
  "statefulsets" in resources
  valueOrWildcard(apiGroups, "apps")
} {
  "deployments" in resources
  valueOrWildcard(apiGroups, "apps")
} {
  "replicasets" in resources
  valueOrWildcard(apiGroups, "apps")
} {
  "replicationcontrollers" in resources
  valueOrWildcard(apiGroups, "")
} {
  podControllerApiGroup(apiGroups)
  hasWildcard(resources)
}


# True if @apiGroups contains a wildcard,
# or an API group that includes a resource that can control pods
podControllerApiGroup(apiGroups) {
  "" in apiGroups
}{
  "apps" in apiGroups
}{
  "batch" in apiGroups
}{
  hasWildcard(apiGroups)
}


# True if @resources includes either 'clusterroles', 'roles', or a wildcard
rolesOrClusterroles(resources) {
  "clusterroles" in resources
} { 
  "roles" in resources
} {
  hasWildcard(resources)
}


# Return the roles referenced by @roleRefs
effectiveRoles(roleRefs) = effectiveRoles {
  effectiveRoles := { effectiveRole | 
    some roleObj in input.roles
    some roleRef in roleRefs
    roleRef.name == roleObj.name
    equalNamespaceIfExist(roleRef, roleObj)
    effectiveRole := buildRole(roleRef, roleObj)
  } 
}

# Builds role from @roleRef and @roleObj
buildRole(roleRef, roleObj) = role {
  not hasKey(roleRef, "effectiveNamespace")
  role := {
      "name": roleRef.name,
      "rules": roleObj.rules
  }
} {
  hasKey(roleRef, "effectiveNamespace")
  role := {
      "name": roleRef.name,
      "effectiveNamespace": roleRef.effectiveNamespace,
      "rules": roleObj.rules
  }
}

# Checks whether @obj and @other have the same namespace
equalNamespaceIfExist(obj, other) {
  obj.namespace == other.namespace
} {
  not hasKey(obj, "namespace")
  not hasKey(other, "namespace")
}

# Checks for LegacyTokenSecretsReducted
legacyTokenSecretsReducted := true {
  metadata := object.get(input, "metadata", {})
  features := object.get(metadata, "features", [])
  "LegacyTokenSecretsReducted" in features
}

# Checks for NodeRestriction
NodeRestriction := true {
  metadata := object.get(input, "metadata", {})
  features := object.get(metadata, "features", [])
  "NodeRestriction" in features
}

# Checks for NodeRestriction1.17
NodeRestrictionV117 := true {
  metadata := object.get(input, "metadata", {})
  features := object.get(metadata, "features", [])
  "NodeRestriction1.17" in features
}

# Permission owner is a node and NodeRestriction is enabled
nodeRestrictionEnabledAndIsNode(permissionOwner) {
  NodeRestriction
  permissionOwner == "node"
}

# Permission owner is a node and NodeRestriction v1.17 is enabled
nodeRestrictionV117EnabledAndIsNode(permissionOwner) {
  NodeRestrictionV117
  permissionOwner == "node"
}
