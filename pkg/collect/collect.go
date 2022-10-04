package collect

import (
	"strings"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // in order to connect to clusters via auth plugins
	"k8s.io/client-go/tools/clientcmd"
)

// Collect retrieves the RBAC settings in a k8s cluster
func Collect(collectConfig CollectConfig) *CollectResult {
	var metadata *ClusterMetadata
	var clusterDb *ClusterDb
	var kubeConfig clientcmd.ClientConfig = nil

	if collectConfig.OfflineDir == "" {
		// Online mode, init Kubernetes client
		clientset, kConfigTmp, err := initKubeClient()
		kubeConfig = kConfigTmp
		if err != nil {
			return nil // error printed in initKubeClient
		}
		// Build metadata and clusterDb from remote cluster
		metadata = buildMetadata(clientset, kubeConfig)
		clusterDb = buildClusterDb(clientset, collectConfig.Namespace, collectConfig.IgnoreControlPlane)
	} else {
		// Offline mode, parse clusterDb and metadata from local files
		clusterDb, metadata = parseLocalCluster(collectConfig)
	}
	if clusterDb == nil {
		return nil // error printed in buildClusterDb or in parseLocalCluster
	}

	if collectConfig.DiscoverProtections {
		discoverRelevantControlPlaneFeatures(collectConfig, kubeConfig, clusterDb, metadata)
	}

	rbacDb := buildRbacDb(*clusterDb, collectConfig)
	if rbacDb == nil {
		return nil // error printed in BuildClusterDb
	}

	return &CollectResult{
		Metadata:        *metadata,
		ServiceAccounts: rbacDb.ServiceAccounts,
		Nodes:           rbacDb.Nodes,
		Users:           rbacDb.Users,
		Groups:          rbacDb.Groups,
		Roles:           rbacDb.Roles,
	}
}

// Initialize the Kubernetes client
func initKubeClient() (*kubernetes.Clientset, clientcmd.ClientConfig, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Errorln("initKubeClient: failed creating ClientConfig with", err)
		return nil, nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorln("initKubeClient: failed creating Clientset with", err)
		return nil, nil, err
	}
	return clientset, kubeConfig, nil
}

// Get cluster metadata
func buildMetadata(clientset *kubernetes.Clientset, kubeConfig clientcmd.ClientConfig) *ClusterMetadata {
	metadata := ClusterMetadata{
		Features: []string{},
	}

	rawConfig, err := kubeConfig.RawConfig()
	if err != nil {
		log.Warnln("getMetadata: failed to get raw kubeconfig", err)
	} else {
		metadata.ClusterName = rawConfig.Contexts[rawConfig.CurrentContext].Cluster
	}

	versionInfo, err := clientset.Discovery().ServerVersion()
	if err != nil {
		log.Warnln("getMetadata: failed to get server version with", err)
	} else {
		metadata.Version = ClusterVersion{
			Major:      versionInfo.Major,
			Minor:      versionInfo.Minor,
			GitVersion: versionInfo.GitVersion,
		}
		metadata.Platform = platformFromVersion(versionInfo.GitVersion)
	}

	return &metadata
}

// Identifies the underlying platform from a cluster's @version,
// supports EKS and GKE
func platformFromVersion(version string) string {
	if strings.Contains(version, "-eks-") {
		return "eks"
	}
	if strings.Contains(version, "-gke.") {
		return "gke"
	}
	return ""
}
