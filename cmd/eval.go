package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
	"github.com/PaloAltoNetworks/rbac-police/pkg/eval"
	"github.com/PaloAltoNetworks/rbac-police/pkg/utils"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// evalCmd represents the eval command
var (
	evalConfig eval.EvalConfig
	shortMode  bool
	violations []string

	evalCmd = &cobra.Command{
		Use:   "eval <policies> [rbac-json]",
		Short: "Evaulates RBAC permissions of Kubernetes identities using Rego policies",
		Run:   runEval,
	}
)

func runEval(cmd *cobra.Command, args []string) {
	var (
		collectResult collect.CollectResult
		output        []byte
		err           error
	)

	if len(args) < 1 {
		fmt.Println("[!] No policies specified")
		cmd.Help()
		return
	}
	policyPath := args[0]

	if len(violations) == 0 {
		fmt.Println("[!] Cannot disable all violation types")
		cmd.Help()
		return
	}

	// Set the violations user asked to search for
	for _, violationType := range violations {
		if violationType == "all" {
			evalConfig.SaViolations = true
			evalConfig.NodeViolations = true
			evalConfig.CombinedViolations = true
			evalConfig.UserViolations = true
			evalConfig.GroupViolations = true
			break
		}
		if violationType == "sa" || violationType == "sas" {
			evalConfig.SaViolations = true
		} else if violationType == "node" || violationType == "nodes" {
			evalConfig.NodeViolations = true
		} else if violationType == "combined" {
			evalConfig.CombinedViolations = true
		} else if violationType == "user" || violationType == "users" {
			evalConfig.UserViolations = true
		} else if violationType == "group" || violationType == "groups" {
			evalConfig.GroupViolations = true
		} else {
			fmt.Printf("[!] Unrecognized violation type '%s', supported types are 'sa', 'node', 'combined', 'user', 'group' or 'all'\n", violationType)
			cmd.Help()
			return
		}
	}

	// Get RBAC input
	if len(args) > 1 {
		// Read RBAC from file
		if collectionOptionsSet() {
			fmt.Println("[!] Can only set collection options when collecting")
			cmd.Help()
			return
		}
		collectResultBytes, err := utils.ReadFile(args[1])
		if err != nil {
			return
		}
		err = json.Unmarshal(collectResultBytes, &collectResult)
		if err != nil {
			log.Errorf("runEval: failed to unmarshel %v into a CollectResult object with %v\n", args[0], err)
			return
		}
	} else {
		// Collect RBAC from remote cluster
		collectResultPtr := collect.Collect(collectConfig)
		if collectResultPtr == nil {
			return // error printed by Collect()
		}
		collectResult = *collectResultPtr
	}

	policyResults := eval.Eval(policyPath, collectResult, evalConfig)
	if policyResults == nil {
		return // error printed by Collect()
	}

	if !shortMode {
		output, err = marshalResults(policyResults)
		if err != nil {
			log.Errorln("runEval: failed to marshal results with", err)
			return
		}
	} else {
		abbreviatedResults := eval.AbbreviateResults(policyResults)
		output, err = marshalResults(abbreviatedResults)
		if err != nil {
			log.Errorln("runEval: failed to marshal abbreviated results with", err)
			return
		}
	}
	outputResults(output)
}

func init() {
	evalCmd.Flags().BoolVar(&shortMode, "short", false, "abbreviate results")
	evalCmd.Flags().BoolVarP(&evalConfig.DebugMode, "debug", "d", false, "debug mode, prints debug info and stdout of policies")
	evalCmd.Flags().BoolVar(&evalConfig.OnlySasOnAllNodes, "only-sas-on-all-nodes", false, "only evaluate serviceAccounts that exist on all nodes")
	evalCmd.Flags().StringVarP(&evalConfig.SeverityThreshold, "severity-threshold", "s", "Low", "only evaluate policies with severity >= threshold")
	evalCmd.Flags().StringSliceVar(&evalConfig.IgnoredNamespaces, "ignored-namespaces", []string{}, "ignore serviceAccounts from certain namespaces during eval") // TODO: consider moving to collect and implement via field selectors
	evalCmd.Flags().StringSliceVar(&violations, "violations", []string{"sa", "node", "combined"}, "violations to search for, beside default supports 'user', 'group' and 'all'")

	rootCmd.AddCommand(evalCmd)
}
