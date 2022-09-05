package collect

import (
	"context"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// buildClusterDb populates a ClusterDb object by querying a cluster
func buildClusterDb(clientset *kubernetes.Clientset, ns string, ignoreControlPlane bool) *ClusterDb {
	var (
		clusterDb ClusterDb
		err       error
	)
	clusterDb.RoleBindings, clusterDb.ClusterRoleBindings, err = getRoleBindingsAndClusterRoleBindings(clientset)
	if err != nil {
		return nil // error printed in getRoleBindingsAndClusterRoleBindings
	}
	clusterDb.Roles, clusterDb.ClusterRoles, err = getRolesAndClusterRoles(clientset)
	if err != nil {
		return nil // error printed in getRolesAndClusterRoles
	}
	clusterDb.ServiceAccounts, err = getServiceAccounts(clientset, ns)
	if err != nil {
		return nil // error printed in getServiceAccounts
	}
	clusterDb.Nodes, err = getNodes(clientset, ignoreControlPlane)
	if err != nil {
		return nil // error printed in getPods
	}
	clusterDb.Pods, err = getPods(clientset, ns)
	if err != nil {
		return nil // error printed in getPods
	}
	if ignoreControlPlane {
		removePodsFromExcludedNodes(&clusterDb) // remove control plane pods if needed
	}
	return &clusterDb
}

// Get all serviceAccounts cluster-wide, or in a namespace if @ns is set
func getServiceAccounts(clientset *kubernetes.Clientset, ns string) ([]v1.ServiceAccount, error) {
	serviceAccountList, err := clientset.CoreV1().ServiceAccounts(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorln("getServiceAccounts: failed to retrieve serviceaccounts with", err)
		return nil, err
	}
	return serviceAccountList.Items, nil
}

// Get all pods cluster-wide, or in a namespace if @ns is set
func getPods(clientset *kubernetes.Clientset, ns string) ([]v1.Pod, error) {
	podList, err := clientset.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorln("getPods: failed to retrieve pods with", err)
		return nil, err
	}
	return podList.Items, nil
}

// Get nodes, drop control plane nodes if @ignoreControlPlane is set
func getNodes(clientset *kubernetes.Clientset, ignoreControlPlane bool) ([]v1.Node, error) {
	listOptions := metav1.ListOptions{}
	if ignoreControlPlane {
		listOptions.LabelSelector = "!node-role.kubernetes.io/master, !node-role.kubernetes.io/control-plane"
	}
	nodeList, err := clientset.CoreV1().Nodes().List(context.Background(), listOptions)
	if err != nil {
		log.Errorln("getNodes: failed to retrieve nodes with", err)
		return nil, err
	}
	return nodeList.Items, nil
}

// Retrieves roles and clusterRoles
func getRolesAndClusterRoles(clientset *kubernetes.Clientset) ([]rbac.Role, []rbac.ClusterRole, error) {
	roleList, err := clientset.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorln("getRolesAndClusterRoles: failed to retrieve roles with", err)
		return nil, nil, err
	}
	clusterRoleList, err := clientset.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorln("getRolesAndClusterRoles: failed to retrieve clusterRoles with", err)
		return nil, nil, err
	}
	return roleList.Items, clusterRoleList.Items, nil
}

// Retrieves roleBindings and clusterRoleBindings
func getRoleBindingsAndClusterRoleBindings(clientset *kubernetes.Clientset) ([]rbac.RoleBinding, []rbac.ClusterRoleBinding, error) {
	roleBindingList, err := clientset.RbacV1().RoleBindings("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorln("getRoleBindingsAndClusterRoleBindings: failed to retrieve roleBindings with", err)
		return nil, nil, err
	}
	clusterRoleBindingList, err := clientset.RbacV1().ClusterRoleBindings().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorln("getRoleBindingsAndClusterRoleBindings: failed to retrieve ClusterroleBindings with", err)
		return nil, nil, err
	}
	return roleBindingList.Items, clusterRoleBindingList.Items, nil
}

// Removes pods that have a NodeName which is not in cDb.Nodes
func removePodsFromExcludedNodes(cDb *ClusterDb) {
	var includedPods []v1.Pod

	for _, pod := range cDb.Pods {
		if pod.Spec.NodeName == "" {
			includedPods = append(includedPods, pod) // include non-scheduled pods
			continue
		}
		for _, node := range cDb.Nodes {
			if pod.Spec.NodeName == node.Name {
				// Pod hosted on included node
				includedPods = append(includedPods, pod)
				break
			}
		}
	}
	cDb.Pods = includedPods
}
