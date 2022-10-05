package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var (
	outFile       string
	loudMode      bool
	jsonIndentLen uint
	collectConfig collect.CollectConfig

	rootCmd = &cobra.Command{
		Use:   "rbac-police",
		Short: "See and evaluate RBAC permissions in Kubernetes clusters",
		Long:  `Retrieves the RBAC permissions of Kubernetes identities and evaluates them using policies written in Rego.`,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outFile, "out-file", "o", "", "save results to file")
	rootCmd.PersistentFlags().BoolVarP(&loudMode, "loud", "l", false, "loud mode, print results regardless of -o")
	rootCmd.PersistentFlags().UintVarP(&jsonIndentLen, "json-indent", "j", 4, "json indent, 0 means compact mode")
	// Collect config
	rootCmd.PersistentFlags().BoolVarP(&collectConfig.AllServiceAccounts, "all-serviceaccounts", "a", false, "collect data on all serviceAccounts, not only those assigned to a pod")
	rootCmd.PersistentFlags().BoolVarP(&collectConfig.DiscoverProtections, "discover-protections", "w", false, "discover features gates and admission controllers that protect against certain attacks, partly by emulating the attacks via impersonation & dry-run write operations")
	rootCmd.PersistentFlags().BoolVar(&collectConfig.IgnoreControlPlane, "ignore-controlplane", false, "don't collect data on control plane nodes and pods. Identified by either the 'node-role.kubernetes.io/control-plane' or 'node-role.kubernetes.io/master' labels. ServiceAccounts will not be linked to control plane components")
	rootCmd.PersistentFlags().StringSliceVar(&collectConfig.NodeGroups, "node-groups", []string{"system:nodes"}, "treat nodes as part of these groups")
	rootCmd.PersistentFlags().StringVar(&collectConfig.NodeUser, "node-user", "", "user assigned to all nodes, default behaviour assumes nodes users are compatible with the NodeAuthorizer")
	rootCmd.PersistentFlags().StringVarP(&collectConfig.Namespace, "namespace", "n", "", "scope collection on serviceAccounts to a namespace")
	rootCmd.PersistentFlags().StringVar(&collectConfig.OfflineDir, "local-dir", "", "offline mode, get cluster data from local files, see <rbac-police>/utils/get_cluster_data.sh")
}

// Prints and / or saves output to file
func outputResults(output []byte) {
	if outFile != "" {
		err := os.WriteFile(outFile, output, 0644)
		if err != nil {
			log.Errorf("runCollect: failed to write results to %v with %v\n", outFile, err)
			return
		}
		if !loudMode {
			return
		}
	}
	fmt.Println(string(output))
}

// Is an option related to collection is set
func collectionOptionsSet() bool {
	return collectConfig.IgnoreControlPlane || collectConfig.AllServiceAccounts ||
		collectConfig.Namespace != "" || collectConfig.NodeUser != "" ||
		(len(collectConfig.NodeGroups) != 1 && collectConfig.NodeGroups[0] != "system:nodes") ||
		collectConfig.DiscoverProtections
}

// Marshal results into a json byte slice, indented based on the global jsonIndentLen variable
func marshalResults(results interface{}) ([]byte, error) {
	if jsonIndentLen > 0 {
		return json.MarshalIndent(results, "", getIndent(jsonIndentLen))
	} else {
		return json.Marshal(results) // compact json output
	}
}

// Create an indent string in the length of @jsonIndentLength, maxed at 12 chars.
func getIndent(jsonIndentLength uint) string {
	return strings.Repeat(" ", int(uintMin(jsonIndentLength, 12)))
}

// Return the minimum number
func uintMin(a uint, b uint) uint {
	if a < b {
		return a
	}
	return b
}
