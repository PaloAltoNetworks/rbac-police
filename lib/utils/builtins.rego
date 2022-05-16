package police_builtins

privileged_namespaces := ["kube-system"]

# True if @arr contains @value or a wildcard
valueOrWildcard(arr, value) {
  arr[_] == value
} {  
  hasWildcard(arr)
}

# True if @arr includes a wildcard
hasWildcard(arr) {
  isWildcard(arr[_])
}

# True if @value is a wildcard
isWildcard(value) {
  value ==  "*"
} # no such thing as */* in K8s RBAC

# True if @obj has a key @k
hasKey(obj, k) {
   _ = obj[k]
}

# True if @role isn't namespaced, or namespaced to a privileged namespace
affectsPrivNS(role) {
  notNamespaced(role)
} {
  privileged_namespaces[_] == role.effectiveNamespace
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
  arr[_] == combinedResourceName
} { 
  subresource := split(combinedResourceName, "/")[1]
  arr[_] == sprintf("*/%v", [subresource])
} {
  hasWildcard(arr)
}

# Returns the SAs from @serviceaccounts that are hosted on the @node
sasOnNode(node) = serviceAccountsOnNode {
  serviceAccountsOnNode = { sa | sa := input.serviceAccounts[_]; 
    fullname := saFullName(sa)
    node.serviceAccounts[_] == fullname
  }
}

# True if @verbs includes either 'update', 'patch' or a wildcard
updateOrPatchOrWildcard(verbs) {
  verbs[_] == "update"
} {
  verbs[_] == "patch"
} { 
  hasWildcard(verbs)
} 

# True if @verbs includes either 'create', 'update', 'patch' or a wildcard
createUpdatePatchOrWildcard(verbs) {
  verbs[_] == "create"
} {
  updateOrPatchOrWildcard(verbs)
}

# True if @verbs includes either 'get', 'list', or a wildcard
getOrListOrWildcard(verbs) {
  verbs[_] == "list"
}{
  verbs[_] == "get"
} {
  hasWildcard(verbs)
}

# True if by any mean, @rule is permitted to overwrite the SA of a pod
ruleCanControlPodSa(rule){
  valueOrWildcard(rule.verbs, "create")
  valueOrWildcard(rule.resources, "pods")
  valueOrWildcard(rule.apiGroups, "")
} {
  podControllerResource(rule.resources, rule.apiGroups)
  createUpdatePatchOrWildcard(rule.verbs)
}

# True if @resources contains a resource that can control pods or a wildcard
podControllerResource(resources, apiGroups) {
  resources[_] == "cronjobs"
  valueOrWildcard(apiGroups, "batch")
} {
  resources[_] == "jobs"
  valueOrWildcard(apiGroups, "batch")
} {
  resources[_] == "daemonsets"
  valueOrWildcard(apiGroups, "apps")
} {
  resources[_] == "statefulsets"
  valueOrWildcard(apiGroups, "apps")
} {
  resources[_] == "deployments"
  valueOrWildcard(apiGroups, "apps")
} {
  resources[_] == "replicasets"
  valueOrWildcard(apiGroups, "apps")
} {
  resources[_] == "replicationcontrollers"
  valueOrWildcard(apiGroups, "")
} {
  podControllerApiGroup(apiGroups)
  hasWildcard(resources)
}


# True if @apiGroups contains a wildcard,
# or an API group that includes a resource that can control pods
podControllerApiGroup(apiGroups) {
  apiGroups[_] == ""
}{
  apiGroups[_] == "apps"
}{
  apiGroups[_] == "batch"
}{
  hasWildcard(apiGroups)
}

# Return the roles referenced by @roleRefs
effectiveRoles(roleRefs) = effectiveRoles {
  effectiveRoles := { effectiveRole | roleObj := input.roles[_] ;
    roleRef := roleRefs[_]
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