package collect

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // in order to connect to clusters via auth plugins
	"k8s.io/client-go/tools/clientcmd"
)

// Collects RBAC permissions in a k8s cluster
func Collect(collectConfig CollectConfig) *CollectResult {
	// Init Kubernetes client
	clientset, kubeConfig, err := initKubeClient()
	if err != nil {
		return nil // error printed in initKubeClient
	}
	metadata := getMetadata(clientset, kubeConfig)
	clusterDb := BuildClusterDb(clientset, collectConfig.Namespace, collectConfig.IgnoreControlPlane)
	if clusterDb == nil {
		return nil // error printed in BuildClusterDb
	}

	rbacDb := BuildRbacDb(*clusterDb, collectConfig)
	if rbacDb == nil {
		return nil // error printed in BuildClusterDb
	}

	return &CollectResult{
		Metadata:        metadata,
		ServiceAccounts: rbacDb.ServiceAccounts,
		Nodes:           rbacDb.Nodes,
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
func getMetadata(clientset *kubernetes.Clientset, kubeConfig clientcmd.ClientConfig) ClusterMetadata {
	versionInfo, err := clientset.Discovery().ServerVersion()
	if err != nil {
		log.Warnln("getMetadata: failed to get server version with", err)
		return ClusterMetadata{}
	}
	rawConfig, err := kubeConfig.RawConfig()
	if err != nil {
		log.Warnln("getMetadata: failed to get raw kubeconfig", err)
		return ClusterMetadata{}
	}

	return ClusterMetadata{
		ClusterName: rawConfig.Contexts[rawConfig.CurrentContext].Cluster,
		Platform:    getPlatform(versionInfo.GitVersion),
		Version:     versionInfo.GitVersion,
	}
}

// Identifies the underlying platform from a cluster's @version,
// supports EKS and GKE
func getPlatform(version string) string {
	if strings.Contains(version, "-eks-") {
		return "eks"
	}
	if strings.Contains(version, "-gke.") {
		return "gke"
	}
	return ""
}
