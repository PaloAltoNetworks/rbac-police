package collect

import (
	"errors"
	"strings"

	"github.com/PaloAltoNetworks/rbac-police/pkg/utils"
	log "github.com/sirupsen/logrus"
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
		if saEntry.Nodes != nil || collectConfig.AllServiceAccounts {
			saEntry.ProviderIAM = getProviderIAM(sa)
			rbacDb.ServiceAccounts = append(rbacDb.ServiceAccounts, saEntry)
		}
	}

	if err := populateRoleBindingsPermissions(&rbacDb, cDb, collectConfig); err != nil {
		return nil // error printed in populateRoleBindingsPermissions
	}
	if err := populateClusterRoleBindingsPermissions(&rbacDb, cDb, collectConfig); err != nil {
		return nil // error printed in populateClusterRoleBindingsPermissions
	}

	return &rbacDb
}

// Incorporates the permission granted by roleBindings into @rbacDb
func populateRoleBindingsPermissions(rbacDb *RbacDb, cDb ClusterDb, collectConfig CollectConfig) error {
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
		roleIsBindedToRelevantSubject := false
		// Check if rb grants role to a serviceAccount
		for i := range rbacDb.ServiceAccounts {
			isSaReferenced, err := isSAReferencedBySubjects(rb.Subjects, utils.FullName(rbacDb.ServiceAccounts[i].Namespace, rbacDb.ServiceAccounts[i].Name), rb.Namespace)
			if err != nil {
				return err
			}
			if isSaReferenced {
				rbacDb.ServiceAccounts[i].Roles = append(rbacDb.ServiceAccounts[i].Roles, roleRef)
				roleIsBindedToRelevantSubject = true
			}
		}
		// Check if rb grants role to a node
		for i := range rbacDb.Nodes {
			if isNodeReferencedBySubjects(rb.Subjects, rbacDb.Nodes[i].Name, collectConfig.NodeGroups, collectConfig.NodeUser) {
				rbacDb.Nodes[i].Roles = append(rbacDb.Nodes[i].Roles, roleRef)
				roleIsBindedToRelevantSubject = true
			}
		}
		// Add role to rbacDb if it's granted to any SA or node
		if roleIsBindedToRelevantSubject {
			addRoleIfDoesntExists(rbacDb, roleEntry)
		}
	}
	return nil
}

// Incorporates the permission granted by clusterRoleBindings into @rbacDb
func populateClusterRoleBindingsPermissions(rbacDb *RbacDb, cDb ClusterDb, collectConfig CollectConfig) error {
	for _, crb := range cDb.ClusterRoleBindings {
		clusterRoleEntry := findClusterRole(cDb.ClusterRoles, crb.RoleRef)
		if clusterRoleEntry.Name == "" {
			continue // binded clusterRole doesn't exist
		}

		clusterRoleRef := RoleRef{ // short version of roleEntry for sa & nodes to point to
			Name: clusterRoleEntry.Name,
		}
		roleIsBindedToRelevantSubject := false
		// Check if the crb grants the cr to a serviceAccount
		for i := range rbacDb.ServiceAccounts {
			isSaReferenced, err := isSAReferencedBySubjects(crb.Subjects, utils.FullName(rbacDb.ServiceAccounts[i].Namespace, rbacDb.ServiceAccounts[i].Name), "")
			if err != nil {
				return err
			}
			if isSaReferenced {
				rbacDb.ServiceAccounts[i].Roles = append(rbacDb.ServiceAccounts[i].Roles, clusterRoleRef)
				roleIsBindedToRelevantSubject = true
			}
		}
		// Check if the crb grants the cr to a node
		for i := range rbacDb.Nodes {
			if isNodeReferencedBySubjects(crb.Subjects, rbacDb.Nodes[i].Name, collectConfig.NodeGroups, collectConfig.NodeUser) {
				rbacDb.Nodes[i].Roles = append(rbacDb.Nodes[i].Roles, clusterRoleRef)
				roleIsBindedToRelevantSubject = true
			}
		}
		// Add cluserRole to rbacDb if it's granted to any SA or node
		if roleIsBindedToRelevantSubject {
			addRoleIfDoesntExists(rbacDb, clusterRoleEntry)
		}
	}
	return nil
}

// Checks whether the serviceAccount denoted by @fullname is refernced in @subjects
func isSAReferencedBySubjects(subjects []rbac.Subject, saFullname string, rbNS string) (bool, error) {
	for _, subject := range subjects {
		if subject.Kind == "ServiceAccount" {
			if subject.Namespace == "" {
				if rbNS == "" {
					// panic
					log.Errorln("isSAReferencedBySubjects: serviceAccount subject must have a namespace as binding doesn't")
					return false, errors.New("serviceAccount subject must have a namespace as binding doesn't")
				}
				subject.Namespace = rbNS
			}
			if saFullname == utils.FullName(subject.Namespace, subject.Name) {
				return true, nil
			}
		} else if subject.Kind == "Group" {
			if subject.Name == "system:authenticated" {
				return true, nil
			}
			if !strings.HasPrefix(subject.Name, "system:serviceaccounts") {
				return false, nil // only handle sa groups
			}
			if subject.Name == "system:serviceaccounts" {
				return true, nil
			}
			if subject.Name == "system:serviceaccounts:"+strings.Split(saFullname, ":")[0] {
				return true, nil
			}
		}
	}
	return false, nil
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
	for i := range rbacDb.Roles {
		if roleEntry.Name == rbacDb.Roles[i].Name && roleEntry.Namespace == (*rbacDb).Roles[i].Namespace {
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
