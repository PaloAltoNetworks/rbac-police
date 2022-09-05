package collect

import (
	"encoding/json"
	"github.com/PaloAltoNetworks/rbac-police/pkg/utils"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/version"
	"os"
	"path"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
)

// parseLocalCluster parses k8s manifests from a local directory into ClusterDb and ClusterMetadata objects
func parseLocalCluster(config CollectConfig) (*ClusterDb, *ClusterMetadata) {
	var versionInfo version.Info
	var inputFiles []string
	metadata := ClusterMetadata{
		Features: []string{},
	}

	// Read local dir
	files, err := os.ReadDir(config.OfflineDir)
	if err != nil {
		log.Errorf("parseLocalCluster: failed to read local dir %q with %v", config.OfflineDir, err)
		return nil, nil
	}

	// Iterate local dir
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if file.Name() == "cluster_name" {
			// Parse cluster_name file into metadata
			if nameBytes, err := os.ReadFile(path.Join(config.OfflineDir, file.Name())); err != nil {
				log.Warnf("parseLocalCluster: failed to read cluster name from local dir  %v", err)
			} else {
				metadata.ClusterName = strings.TrimSuffix(string(nameBytes), "\n")
			}
		} else if file.Name() == "version.json" {
			// Parse version.json file into metadata
			if versionBytes, err := os.ReadFile(path.Join(config.OfflineDir, file.Name())); err != nil {
				log.Warnf("parseLocalCluster: failed to read version.json with %v\n", err)
			} else {
				err = json.Unmarshal(versionBytes, &versionInfo)
				if err != nil {
					log.Warnf("parseLocalCluster: failed to unmarshal %s into a version.Info obj with %v\n", file.Name(), err)
				} else {
					metadata.Version = ClusterVersion{
						Major:      versionInfo.Major,
						Minor:      versionInfo.Minor,
						GitVersion: versionInfo.GitVersion,
					}
					metadata.Platform = platformFromVersion(versionInfo.GitVersion)
				}
			}
		} else if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".json") {
			// Add input files (e.g. 'pods.json', 'nodes.yaml', etc.)
			inputFiles = append(inputFiles, path.Join(config.OfflineDir, file.Name()))
		}
	}
	if len(inputFiles) != 7 {
		log.Errorf("parseLocalCluster: expected 7 input files, got %d\n", len(inputFiles))
		return nil, nil
	}
	clusterDb := clusterDbFromLocalFiles(inputFiles, config)
	return clusterDb, &metadata
}

// Creates a ClusterDb object from @inputFiles
func clusterDbFromLocalFiles(inputFiles []string, config CollectConfig) *ClusterDb {
	var clusterDb ClusterDb

	// Prepare a scheme containing all the objects we need to decode
	scheme := returnScheme()
	if scheme == nil {
		return nil // err printed in returnScheme
	}
	decodeFunc := serializer.NewCodecFactory(scheme).UniversalDeserializer().Decode

	// Go over files
	for _, filePath := range inputFiles {
		// Read file
		inputBytes, err := utils.ReadFile(filePath)
		if err != nil {
			return nil
		}
		// Decode the file's contents into a *v1.List
		decodedBytes, _, err := decodeFunc(inputBytes, nil, nil)
		if err != nil {
			log.Errorf("clusterDbFromLocalFiles: error while decoding %s: %v\n", filePath, err)
			return nil
		}
		switch list := decodedBytes.(type) {
		case *v1.List:
			// Iterate list items and try to decode each into an expected input type
			for i, item := range list.Items {
				decodedObj, _, err := decodeFunc(item.Raw, nil, nil)
				if err != nil {
					log.Errorf("clusterDbFromLocalFiles: error while decoding %s items[%d].Raw: %v\n", filePath, i, err)
					return nil
				}
				switch item := decodedObj.(type) {
				case *v1.Pod:
					if config.Namespace != "" && item.ObjectMeta.Namespace != config.Namespace {
						continue // don't add pod if it's not in the ns the collection is scoped to
					}
					clusterDb.Pods = append(clusterDb.Pods, *item)
				case *v1.Node:
					if config.IgnoreControlPlane {
						for label := range item.ObjectMeta.Labels {
							if label == "node-role.kubernetes.io/master" || label == "node-role.kubernetes.io/control-plane" {
								continue // skip control plane nodes if asked to
							}
						}
					}
					clusterDb.Nodes = append(clusterDb.Nodes, *item)
				case *v1.ServiceAccount:
					if config.Namespace != "" && item.ObjectMeta.Namespace != config.Namespace {
						continue // don't add SA if it's not in the ns the collection is scoped to
					}
					clusterDb.ServiceAccounts = append(clusterDb.ServiceAccounts, *item)
				case *rbac.ClusterRole:
					clusterDb.ClusterRoles = append(clusterDb.ClusterRoles, *item)
				case *rbac.Role:
					clusterDb.Roles = append(clusterDb.Roles, *item)
				case *rbac.ClusterRoleBinding:
					clusterDb.ClusterRoleBindings = append(clusterDb.ClusterRoleBindings, *item)
				case *rbac.RoleBinding:
					clusterDb.RoleBindings = append(clusterDb.RoleBindings, *item)
				default:
					log.Errorf("clusterDbFromLocalFiles: unexpected type while decoding %s items[%d], got %s\n", filePath, i, reflect.TypeOf(decodedObj))
					return nil
				}
			}
		default:
			log.Errorf("clusterDbFromLocalFiles: unexpected type decoding %s, expected *v1.List, got %s\n", filePath, reflect.TypeOf(decodedBytes))
			return nil
		}
	}
	if config.IgnoreControlPlane {
		removePodsFromExcludedNodes(&clusterDb) // remove control plane pods if needed
	}
	return &clusterDb
}

// Returns a scheme describing the objects we want to decode
func returnScheme() *runtime.Scheme {
	schemes := runtime.NewScheme()
	if err := v1.AddToScheme(schemes); err != nil {
		log.Errorf("returnScheme: failed to add the core v1 scheme with %v\n", err)
		return nil
	}
	if err := rbac.AddToScheme(schemes); err != nil {
		log.Errorf("returnScheme: failed to add the rbac v1 scheme with %v\n", err)
		return nil
	}
	return schemes
}
