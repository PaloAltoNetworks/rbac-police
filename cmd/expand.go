package cmd

import (
	"encoding/json"
	"fmt"

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
		Short: "Presents the RBAC permissions of serviceAccounts, pods and nodes in a human-readable format",
		Run:   runExpand,
	}
)

func runExpand(cmd *cobra.Command, args []string) {
	var (
		collectResult collect.CollectResult
	)

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

	expandResult := expand.Expand(collectResult)
	if expandResult == nil {
		return // error printed by Expand()
	}
	output, err := json.MarshalIndent(expandResult, "", "    ")
	if err != nil {
		log.Errorln("runExpand: failed to marshal results with", err)
		return
	}
	outputResults(output)
}

func init() {
	rootCmd.AddCommand(expandCmd)
}
