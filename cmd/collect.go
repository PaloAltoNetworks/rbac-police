package cmd

import (
	"encoding/json"

	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// collectCmd represents the collect command
var (
	collectCmd = &cobra.Command{
		Use:   "collect",
		Short: "Collects the RBAC permissions of Kubernetes identities",
		Run:   runCollect,
	}
)

func runCollect(cmd *cobra.Command, args []string) {
	collectResult := collect.Collect(collectConfig)
	if collectResult == nil {
		return // error printed by Collect()
	}
	output, err := json.Marshal(collectResult)
	if err != nil {
		log.Errorln("runCollect: failed to marshal results with", err)
		return
	}
	outputResults(output)
}

func init() {
	rootCmd.AddCommand(collectCmd)
}
