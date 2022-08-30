package collect

import (
	"k8s.io/client-go/kubernetes"
)

// Discover control plane feature gates and admission controllers that protect against certain attacks,
// and populate the cluster's metadata with them for policies to consume.
// NOTE: Uses impersonation and dry-run write operations, which won't affect the cluster, but may be logged / audited on.
func discoverRelevantControlPlaneFeatures(clientset *kubernetes.Clientset, clusterDb *ClusterDb, metadata *ClusterMetadata) {
	if legacyTokenSecretsReducted(clusterDb) {
		metadata.Features = append(metadata.Features, "LegacyTokenSecretsReducted")
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
