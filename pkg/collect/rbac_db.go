package collect

import (
	"strings"

	"github.com/PaloAltoNetworks/rbac-police/pkg/utils"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
)

// buildRbacDb populates a RbacDb object from a ClusterDb according to config
func buildRbacDb(cDb ClusterDb, collectConfig CollectConfig) *RbacDb {
	var rbacDb RbacDb

	for _, node := range cDb.Nodes {
		rbacDb.Nodes = append(rbacDb.Nodes, NodeEntry{Name: node.Name, ServiceAccounts: []string{}})
	}

	for _, sa := range cDb.ServiceAccounts {
		saEntry := ServiceAccountEntry{
			Name:      sa.Name,
			Namespace: sa.Namespace,
		}
		// Add pods that are assigned the SA
		for _, pod := range cDb.Pods {
			if saEntry.Equals(pod.Spec.ServiceAccountName, pod.ObjectMeta.Namespace) {
				newNodeForSA := true
				for i := range saEntry.Nodes {
					if saEntry.Nodes[i].Name == pod.Spec.NodeName {
						saEntry.Nodes[i].Pods = append(saEntry.Nodes[i].Pods, pod.ObjectMeta.Name)
						newNodeForSA = false
						break
					}
				}
				if newNodeForSA {
					saEntry.Nodes = append(saEntry.Nodes, NodeToPods{Name: pod.Spec.NodeName, Pods: []string{pod.ObjectMeta.Name}})
					for i := range rbacDb.Nodes {
						if rbacDb.Nodes[i].Name == pod.Spec.NodeName {
							rbacDb.Nodes[i].ServiceAccounts = append(rbacDb.Nodes[i].ServiceAccounts, utils.FullName(saEntry.Namespace, saEntry.Name))
							break
						}
					}
				}
			}
		}
		// Add SA if it's assigned to a pod or if we're configured to always collect
		if saEntry.Nodes != nil || collectConfig.AllServiceAccounts {
			saEntry.ProviderIAM = getProviderIAM(sa)
			rbacDb.ServiceAccounts = append(rbacDb.ServiceAccounts, saEntry)
		}
	}

	populateRoleBindingsPermissions(&rbacDb, cDb, collectConfig)
	populateClusterRoleBindingsPermissions(&rbacDb, cDb, collectConfig)

	return &rbacDb
}

// Incorporates the permission granted by roleBindings into @rbacDb
func populateRoleBindingsPermissions(rbacDb *RbacDb, cDb ClusterDb, collectConfig CollectConfig) {
	for _, rb := range cDb.RoleBindings {
		var roleEntry RoleEntry
		if rb.RoleRef.Kind == "ClusterRole" {
			roleEntry = findClusterRole(cDb.ClusterRoles, rb.RoleRef)
		} else if rb.RoleRef.Kind == "Role" {
			roleEntry = findRole(cDb.Roles, rb.RoleRef, rb.ObjectMeta.Namespace)
		}
		if roleEntry.Name == "" {
			continue // binded role doesn't exist
		}

		roleRef := RoleRef{ // short version of roleEntry for sa & nodes to point to
			Name:               roleEntry.Name,
			Namespace:          roleEntry.Namespace,
			EffectiveNamespace: rb.ObjectMeta.Namespace,
		}
		roleBindedToRelevantSubject := false

		// Check if rb grants role to a serviceAccount
		for i, sa := range rbacDb.ServiceAccounts {
			if isSAReferencedBySubjects(rb.Subjects, utils.FullName(sa.Namespace, sa.Name), rb.Namespace) {
				rbacDb.ServiceAccounts[i].Roles = append(rbacDb.ServiceAccounts[i].Roles, roleRef)
				roleBindedToRelevantSubject = true
			}
		}
		// Check if rb grants role to a node
		for i, node := range rbacDb.Nodes {
			if isNodeReferencedBySubjects(rb.Subjects, node.Name, collectConfig.NodeGroups, collectConfig.NodeUser) {
				rbacDb.Nodes[i].Roles = append(rbacDb.Nodes[i].Roles, roleRef)
				roleBindedToRelevantSubject = true
			}
		}

		// Check if rb grants role to a user or group
		for _, subject := range rb.Subjects {
			if subject.Kind == "User" {
				userAlreadyInDb := false
				roleBindedToRelevantSubject = true
				for i, user := range rbacDb.Users {
					if subject.Name == user.Name {
						rbacDb.Users[i].Roles = append(rbacDb.Users[i].Roles, roleRef)
						userAlreadyInDb = true
						break // found user, break
					}
				}
				if !userAlreadyInDb { // add user to RbacDb if encountered it for the first time
					rbacDb.Users = append(rbacDb.Users, NamedEntry{Name: subject.Name, Roles: []RoleRef{roleRef}})
				}
			} else if subject.Kind == "Group" {
				if subject.Name == "system:masters" {
					continue // ignore system:masters to reduce clutter
				}
				grpAlreadyInDb := false
				roleBindedToRelevantSubject = true
				for i, grp := range rbacDb.Groups {
					if subject.Name == grp.Name {
						rbacDb.Groups[i].Roles = append(rbacDb.Groups[i].Roles, roleRef)
						grpAlreadyInDb = true
						break // found group, break
					}
				}
				if !grpAlreadyInDb { // add grp to RbacDb if encountered it for the first time
					rbacDb.Groups = append(rbacDb.Groups, NamedEntry{Name: subject.Name, Roles: []RoleRef{roleRef}})
				}
			}

		}
		// Add role to rbacDb if it's granted to any SA or node
		if roleBindedToRelevantSubject {
			addRoleIfDoesntExists(rbacDb, roleEntry)
		}
	}
}

// Incorporates the permission granted by clusterRoleBindings into @rbacDb
func populateClusterRoleBindingsPermissions(rbacDb *RbacDb, cDb ClusterDb, collectConfig CollectConfig) {
	for _, crb := range cDb.ClusterRoleBindings {
		clusterRoleEntry := findClusterRole(cDb.ClusterRoles, crb.RoleRef)
		if clusterRoleEntry.Name == "" {
			continue // binded clusterRole doesn't exist
		}
		clusterRoleRef := RoleRef{ // short version of roleEntry for sa & nodes to point to
			Name: clusterRoleEntry.Name,
		}
		roleBindedToRelevantSubject := false

		// Check if the crb grants the cr to a serviceAccount
		for i, sa := range rbacDb.ServiceAccounts {
			if isSAReferencedBySubjects(crb.Subjects, utils.FullName(sa.Namespace, sa.Name), "") {
				rbacDb.ServiceAccounts[i].Roles = append(rbacDb.ServiceAccounts[i].Roles, clusterRoleRef)
				roleBindedToRelevantSubject = true
			}
		}
		// Check if the crb grants the cr to a node
		for i, node := range rbacDb.Nodes {
			if isNodeReferencedBySubjects(crb.Subjects, node.Name, collectConfig.NodeGroups, collectConfig.NodeUser) {
				rbacDb.Nodes[i].Roles = append(rbacDb.Nodes[i].Roles, clusterRoleRef)
				roleBindedToRelevantSubject = true
			}
		}

		// Check if crb grants ClusterRole to a user or group
		for _, subject := range crb.Subjects {
			if subject.Kind == "User" {
				userAlreadyInDb := false
				roleBindedToRelevantSubject = true
				for i, user := range rbacDb.Users {
					if subject.Name == user.Name {
						rbacDb.Users[i].Roles = append(rbacDb.Users[i].Roles, clusterRoleRef)
						userAlreadyInDb = true
						break
					}
				}
				if !userAlreadyInDb {
					rbacDb.Users = append(rbacDb.Users, NamedEntry{Name: subject.Name, Roles: []RoleRef{clusterRoleRef}})
				}
			} else if subject.Kind == "Group" {
				if subject.Name == "system:masters" {
					continue // ignore system:masters to reduce clutter
				}
				grpAlreadyInDb := false
				roleBindedToRelevantSubject = true
				for i, grp := range rbacDb.Groups {
					if subject.Name == grp.Name {
						rbacDb.Groups[i].Roles = append(rbacDb.Groups[i].Roles, clusterRoleRef)
						grpAlreadyInDb = true
						break
					}
				}
				if !grpAlreadyInDb {
					rbacDb.Groups = append(rbacDb.Groups, NamedEntry{Name: subject.Name, Roles: []RoleRef{clusterRoleRef}})
				}
			}
		}

		// Add clusterRole to rbacDb if it's granted to any SA or node
		if roleBindedToRelevantSubject {
			addRoleIfDoesntExists(rbacDb, clusterRoleEntry)
		}
	}
}

// Checks whether the serviceAccount denoted by @fullname is refernced in @subjects
func isSAReferencedBySubjects(subjects []rbac.Subject, saFullname string, rbNS string) bool {
	for _, subject := range subjects {
		if subject.Kind == "ServiceAccount" {
			if subject.Namespace == "" {
				subject.Namespace = rbNS
			}
			if saFullname == utils.FullName(subject.Namespace, subject.Name) {
				return true
			}
		} else if subject.Kind == "Group" {
			if subject.Name == "system:authenticated" {
				return true
			}
			if !strings.HasPrefix(subject.Name, "system:serviceaccounts") {
				return false // only handle sa groups
			}
			if subject.Name == "system:serviceaccounts" {
				return true
			}
			if subject.Name == "system:serviceaccounts:"+strings.Split(saFullname, ":")[0] {
				return true
			}
		}
	}
	return false
}

// Checks whether the node denoted by @nodeName is refernced in @subjects
func isNodeReferencedBySubjects(subjects []rbac.Subject, nodeName string, nodeGroups []string, nodeUser string) bool {
	for _, subject := range subjects {
		if subject.Kind == "User" {
			if nodeUser != "" {
				if subject.Name == nodeUser {
					return true
				}
			} else {
				if subject.Name == "system:node:"+nodeName {
					return true
				}
			}
		} else if subject.Kind == "Group" {
			if subject.Name == "system:authenticated" {
				return true
			}
			for _, grp := range nodeGroups {
				if subject.Name == grp {
					return true
				}
			}
		}
	}
	return false
}

// Adds @role entry to @rbacDb if it's not already there
func addRoleIfDoesntExists(rbacDb *RbacDb, roleEntry RoleEntry) {
	for _, role := range rbacDb.Roles {
		if roleEntry.Name == role.Name && roleEntry.Namespace == role.Namespace {
			return
		}
	}
	rbacDb.Roles = append(rbacDb.Roles, roleEntry)
}

// Identifies IAM roles granted to a @serviceAccount through annotaions,
// Supports EKS and GKE annotations
func getProviderIAM(serviceAccount v1.ServiceAccount) map[string]string {
	providerIAM := make(map[string]string)
	for key, value := range serviceAccount.ObjectMeta.Annotations {
		if key == "eks.amazonaws.com/role-arn" {
			providerIAM["aws"] = value
		} else if key == "iam.gke.io/gcp-service-account" {
			providerIAM["gcp"] = value
		}
	}
	return providerIAM
}

// Find clusterRole refrenced by @ref
func findClusterRole(clusterRoles []rbac.ClusterRole, ref rbac.RoleRef) RoleEntry {
	var clusterRoleEntry RoleEntry
	for _, cr := range clusterRoles {
		if cr.Name == ref.Name {
			clusterRoleEntry.Name = cr.ObjectMeta.Name
			clusterRoleEntry.Rules = cr.Rules
			break
		}
	}
	return clusterRoleEntry
}

// Find role in @ns refrenced by @ref
// Need @ns as ref.Namespace doesn't necessarily exist
func findRole(roles []rbac.Role, ref rbac.RoleRef, ns string) RoleEntry {
	var roleEntry RoleEntry
	for _, role := range roles {
		if role.Name == ref.Name && role.Namespace == ns {
			roleEntry.Name = role.ObjectMeta.Name
			roleEntry.Namespace = ns
			roleEntry.Rules = role.Rules
			break
		}
	}
	return roleEntry
}
