package collect

import (
	"context"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Discover control plane feature gates and admission controllers that protect against certain attacks,
// and populate the cluster's metadata with them for policies to consume.
// NOTE: Uses impersonation and dry-run write operations, which won't affect the cluster, but may be logged / audited on.
func discoverRelevantControlPlaneFeatures(collectConfig CollectConfig, kubeConfig clientcmd.ClientConfig, clusterDb *ClusterDb, metadata *ClusterMetadata) {
	if legacyTokenSecretsReducted(clusterDb) {
		metadata.Features = append(metadata.Features, "LegacyTokenSecretsReducted")
	}
	// If NodeAuthorization is used, check for NodeRestriction
	if collectConfig.NodeUser == "" {
		if NodeRestrictionEnabled(kubeConfig, clusterDb, metadata) {
			metadata.Features = append(metadata.Features, "NodeRestriction")
			// If the cluster's version >=1.17, populate NodeRestriction1.17
			major, err := strconv.Atoi(metadata.Version.Major)
			if err == nil {
				minor, err := strconv.Atoi(metadata.Version.Minor)
				if err == nil {
					if major > 1 || minor >= 17 {
						metadata.Features = append(metadata.Features, "NodeRestriction1.17")
					}
				}
			}
		}
	}
}

// Best effort test for whether serviceAccount tokens are stored as secrets
func legacyTokenSecretsReducted(clusterDb *ClusterDb) bool {
	for _, serviceAccount := range clusterDb.ServiceAccounts {
		if serviceAccount.ObjectMeta.Namespace != "kube-system" {
			continue
		}
		// Arbitrarily chose the replicaset-controller for testing
		if serviceAccount.ObjectMeta.Name != "replicaset-controller" {
			continue
		}
		// Return true if there are no auto-generated secrets for the serviceAccount
		return len(serviceAccount.Secrets) == 0
	}
	return false
}

// Some variables for the NodeRestriction check
var mirrorPodAnnotationErrMsg = "pod does not have \"kubernetes.io/config.mirror\" annotation"
var dryRunName = "rbac-police-dry-run-test-pod"
var testPodSpec = &v1.Pod{
	ObjectMeta: metav1.ObjectMeta{
		Name: dryRunName,
	},
	Spec: v1.PodSpec{
		Containers: []v1.Container{
			{
				Name:  dryRunName,
				Image: dryRunName,
			},
		},
	},
}

// Check if NodeRestriction is enabled by impersonating a node and creating a non-mirror pod
func NodeRestrictionEnabled(kubeConfig clientcmd.ClientConfig, clusterDb *ClusterDb, metadata *ClusterMetadata) bool {
	if len(clusterDb.Nodes) == 0 {
		return false
	}

	// Create client that impersonates a node
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return false
	}
	config.Impersonate = rest.ImpersonationConfig{
		UserName: "system:node:" + clusterDb.Nodes[0].ObjectMeta.Name,
		Groups:   []string{"system:nodes", "system:authenticated"},
	}
	attackNodeClientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false
	}
	attackNodePodClient := attackNodeClientSet.CoreV1().Pods("default")

	// Dry run create the test pod
	dryRunCreate := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	_, err = attackNodePodClient.Create(context.Background(), testPodSpec, dryRunCreate)
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), mirrorPodAnnotationErrMsg)
}
