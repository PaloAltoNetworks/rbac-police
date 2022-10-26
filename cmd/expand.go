package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
	"github.com/PaloAltoNetworks/rbac-police/pkg/expand"
	"github.com/PaloAltoNetworks/rbac-police/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// expandCmd represents the expand command
var (
	expandCmd = &cobra.Command{
		Use:   "expand [rbac-json]",
		Short: "Presents the RBAC permissions of Kubernetes identities in a (more) human-readable format",
		Long: `Presents the RBAC permissions of Kubernetes identities in a (more) human-readable format for manual drill down.
This is done by repeating the entire permissions of each role under each identity that has it.`,
		Run: runExpand,
	}

	zoomedIdentity string
)

func runExpand(cmd *cobra.Command, args []string) {
	var (
		collectResult   collect.CollectResult
		output          []byte
		err             error
		zoomedType      string
		zoomedName      string
		zoomedNamespace string
	)

	// If zoomedIdentity is used, parse it
	if zoomedIdentity != "" {
		zoomedType, zoomedName, zoomedNamespace = parseZoomedIdentity(zoomedIdentity)
		if zoomedType == "" {
			cmd.Help()
			return
		}
	}

	// Get RBAC JSON
	if len(args) > 0 {
		if collectionOptionsSet() {
			fmt.Println("[!] Can only set collection options when collecting")
			cmd.Help()
			return
		}
		collectResultBytes, err := utils.ReadFile(args[0])
		if err != nil {
			return
		}
		err = json.Unmarshal(collectResultBytes, &collectResult)
		if err != nil {
			log.Errorf("runExpand: failed to unmarshel %v into a CollectResult object with %v\n", args[0], err)
			return
		}
	} else {
		collectResultPtr := collect.Collect(collectConfig)
		if collectResultPtr == nil {
			return // error printed by Collect()
		}
		collectResult = *collectResultPtr
	}

	// Expand collection results
	expandResult := expand.Expand(collectResult)
	if expandResult == nil {
		return // error printed by Expand()
	}

	// Marshal results
	if zoomedIdentity == "" {
		output, err = marshalResults(expandResult)
	} else {
		// Zoom on a specific identity  // TODO: consider only collecting / expanding the zoomed identity
		if zoomedType == "sa" {
			for _, sa := range expandResult.ServiceAccounts {
				if sa.Name == zoomedName && sa.Namespace == zoomedNamespace {
					output, err = marshalResults(sa)
					break
				}
			}
		} else if zoomedType == "node" {
			for _, node := range expandResult.Nodes {
				if node.Name == zoomedName {
					output, err = marshalResults(node)
					break
				}
			}
		} else if zoomedType == "user" {
			for _, user := range expandResult.Users {
				if user.Name == zoomedName {
					output, err = marshalResults(user)
					break
				}
			}
		} else if zoomedType == "group" {
			for _, grp := range expandResult.Groups {
				if grp.Name == zoomedName {
					output, err = marshalResults(grp)
					break
				}
			}
		}
		if len(output) == 0 {
			fmt.Println("[!] Cannot find zoomed identity")
			return
		}
	}

	// Output expand results
	if err != nil {
		log.Errorln("runExpand: failed to marshal results with", err)
		return
	}
	outputResults(output)
}

func init() {
	expandCmd.Flags().StringVarP(&zoomedIdentity, "zoom", "z", "", "only show the permissions of the specified identity, format is 'type=identity', e.g. 'sa=kube-system:default', 'user=example@email.com'")
	rootCmd.AddCommand(expandCmd)
}

// Parses zoomedIdentity into a type, identity and namespace
func parseZoomedIdentity(zoomedIdentity string) (string, string, string) {
	var zoomedNamespace string

	// Parse type & name
	separatorIndex := strings.Index(zoomedIdentity, "=")
	if separatorIndex < 0 {
		fmt.Println("[!] Cannot parse zoomed identity, format is 'type=identity'")
		return "", "", ""
	}
	zoomedType := zoomedIdentity[:separatorIndex]
	zoomedName := zoomedIdentity[separatorIndex+1:]

	// Parse namespace for service accounts
	if zoomedType == "sa" {
		separatorIndex = strings.Index(zoomedName, ":")
		if separatorIndex < 0 {
			fmt.Println("[!] Cannot parse zoomed SA, format is 'sa=namespace:name'")
			return "", "", ""
		}
		zoomedNamespace = zoomedName[:separatorIndex]
		zoomedName = zoomedName[separatorIndex+1:]
	} else if zoomedType != "node" && zoomedType != "user" && zoomedType != "group" {
		fmt.Printf("[!] Unsupported type for zoomed identity '%s', supported types are 'sa', 'node', 'user' and 'group'\n", zoomedType)
		return "", "", ""
	}
	return zoomedType, zoomedName, zoomedNamespace
}
