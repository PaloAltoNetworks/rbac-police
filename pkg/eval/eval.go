package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"strings"

	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
	"github.com/PaloAltoNetworks/rbac-police/pkg/utils"
	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	log "github.com/sirupsen/logrus"
)

var (
	// Hash set of dirs to ignore when looking for
	// policy files under a path
	ignoredDirs = map[string]struct{}{
		"ignore": {},
		"utils":  {},
	}
	severityMap     = map[string]int{"Low": 1, "Medium": 2, "High": 3, "Critical": 4, "": 5}
	builtinsLibPath = "lib/utils/builtins.rego" // TODO: move out of eval.go / make configurable / go-bindata
)

// Evaluates RBAC permissions using Rego policies
func Eval(policyPath string, collectResult collect.CollectResult, evalConfig EvalConfig) *PolicyResults {
	// Set debug mode
	if evalConfig.DebugMode {
		log.SetLevel(log.DebugLevel)
	}

	// Remove identities that we're not going to evaluate per the `--violations` flag
	removedUnneededIdentities(&collectResult, evalConfig)

	// Enforce evalConfig.OnlySasOnAllNodes
	if evalConfig.OnlySasOnAllNodes {
		filterOnlySasOnAllNodes(&collectResult)
	}

	// Enforce evalConfig.IgnoredNamespaces
	if len(evalConfig.IgnoredNamespaces) > 0 {
		ignoreNamespaces(&collectResult, evalConfig.IgnoredNamespaces)
	}

	// Since the above functions might have removed some identities, we could have dangling roles that are no longer referenced
	purgeDanglingRoles(&collectResult)

	// Decode input json
	var rbacJson interface{}
	rbacBytes, err := json.Marshal(collectResult)
	if err != nil {
		log.Errorf("Eval: failed to marshal CollectResult object with %v\n", err)
		return nil
	}
	d := json.NewDecoder(bytes.NewBuffer(rbacBytes))
	if err := d.Decode(&rbacJson); err != nil {
		log.Errorln("eval: failed to decode rbac json with", err)
		return nil
	}

	// Get the list of policies to evaluate
	policyFiles, err := getPolicyFiles(policyPath, ignoredDirs)
	if err != nil {
		return nil
	}
	if len(policyFiles) == 0 {
		log.Errorln("eval: couldn't find policy files with '.rego' suffix under", policyPath)
		return nil
	}

	// Prepare configuration for policies
	policyConfig := fmt.Sprintf(`{
		"config": {
			"evalSaViolations": %t,
			"evalNodeViolations": %t,
			"evalCombinedViolations": %t,
			"evalUserViolations": %t,
			"evalGroupViolations": %t
		}
	}`, evalConfig.SaViolations, evalConfig.NodeViolations, evalConfig.CombinedViolations, evalConfig.UserViolations, evalConfig.GroupViolations)

	// Run policies against input json
	var policyResults PolicyResults
	failedPolicies, errorsCounter, belowThresholdPolicies := 0, 0, 0
	for _, policyFile := range policyFiles {
		log.Debugf("eval: running policy %v...\n", policyFile)
		currPolicyResult, err := runPolicy(policyFile, rbacJson, policyConfig, evalConfig)
		if err != nil {
			switch err.(type) {
			default:
				errorsCounter += 1
			case *belowThresholdErr:
				belowThresholdPolicies += 1 // unused
			}
			continue
		}
		if currPolicyResult != nil {
			failedPolicies += 1
			policyResults.PolicyResults = append(policyResults.PolicyResults, *currPolicyResult)
		}
	}

	// Summarize
	policyResults.Summary = Summary{
		Evaluated: len(policyFiles),
		Failed:    failedPolicies,
		Passed:    len(policyFiles) - failedPolicies - errorsCounter,
		Errors:    errorsCounter,
	}

	return &policyResults
}

// Runs a Rego policy on @rbacJson
func runPolicy(policyFile string, rbacJson interface{}, policyConfig string, evalConfig EvalConfig) (*PolicyResult, error) {
	policyResult := PolicyResult{PolicyFile: policyFile}

	// Get policy description & severity
	desc := describePolicy(policyFile)
	if desc != nil {
		policyResult.Severity = desc.Severity
		policyResult.Description = desc.Description
	}

	// Don't evaluate if severity is under threshold
	if severityMap[policyResult.Severity] < severityMap[evalConfig.SeverityThreshold] {
		return nil, &belowThresholdErr{}
	}

	// Evaluate policy
	violations, err := evaluatePolicy(policyFile, rbacJson, policyConfig, evalConfig)
	if violations == nil || err != nil {
		return nil, err
	}

	policyResult.Violations = *violations
	return &policyResult, nil
}

// Get policy's description and severity
func describePolicy(policyFile string) *DescribeRegoResult {
	// Prepare query
	var desc DescribeRegoResult
	describeQuery, err := rego.New(
		rego.Query("data.policy.describe[_]"),
		rego.Load([]string{policyFile, builtinsLibPath}, nil),
	).PrepareForEval(context.Background())
	if err != nil {
		log.Debugf("describePolicy: error preparing query for %v with %v\n", policyFile, err)
		return nil
	}

	// Run describe query
	rs, err := describeQuery.Eval(context.Background())
	if err != nil {
		log.Debugf("describePolicy: failed to evaluate query for %v with %v\n", policyFile, err)
		return nil
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil // no results
	}
	log.Debugf("describePolicy: results for %v:\n", policyFile)
	logResults(rs)

	err = mapstructure.Decode(rs[0].Expressions[0].Value, &desc)
	if err != nil {
		log.Debugf("describePolicy: failed to decode results for %v with %v\n", policyFile, err)
		return nil
	}
	return &desc
}

// Evaluate policy on @input, return violations
func evaluatePolicy(policyFile string, input interface{}, policyConfig string, evalConfig EvalConfig) (*Violations, error) {
	var (
		foundViolations = false
		violations      Violations
		queryStr        string
		regoFiles       = []string{policyFile, builtinsLibPath}
		ctx             = context.Background()
	)

	// Read policy file
	policyBytes, err := utils.ReadFile(policyFile)
	if err != nil {
		return nil, err
	}
	policy := string(policyBytes)

	// Wrap policy if needed
	if policyNeedsWrapping(policy) {
		regoFiles = append([]string{wrapperFile}, regoFiles...)
		queryStr = "data.wrapper.main[_]"
	} else {
		queryStr = "data.policy.main[_]"
	}

	// Manually create storage in-memory, write policyConfig into it, and set up a writable transaction for Load()
	store := inmem.NewFromReader(bytes.NewBufferString(policyConfig))
	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		log.Errorf("evaluatePolicy: error preparing transaction for %v with %v\n", policyFile, err)
		return nil, err
	}

	// Prepare query
	var policyStdoutBuf bytes.Buffer // collect debug output
	query, err := rego.New(
		rego.Query(queryStr),
		rego.Store(store),
		rego.Transaction(txn),
		rego.Load(regoFiles, nil),
		rego.EnablePrintStatements(true),
		rego.PrintHook(topdown.NewPrintHook(&policyStdoutBuf)),
	).PrepareForEval(ctx)
	if err != nil {
		log.Errorf("evaluatePolicy: error preparing query for %v with %v\n", policyFile, err)
		return nil, err
	}

	// Evaluate policy over input
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if policyStdoutBuf.Len() > 0 {
		log.Debugln("evaluatePolicy: output from", policyFile)
		log.Debugf(policyStdoutBuf.String())
	}
	if err != nil {
		log.Errorf("evaluatePolicy: failed to evaluate query for %v with %v\n", policyFile, err)
		return nil, err
	}
	if len(rs) == 0 { // no results
		log.Debugln("evaluatePolicy: no results for", policyFile)
		return nil, err
	}
	log.Debugf("evaluatePolicy: results for %v:\n", policyFile)
	logResults(rs)

	// Parse results for violations
	for _, result := range rs {
		var (
			tmpInterface   interface{}
			currViolations EvalRegoResult
		)
		// Our query contains one expression, main[_], so we only assess the first (and only) expression in the result
		tmpInterface, ok := result.Expressions[0].Value.(map[string]interface{})["violations"]
		if !ok {
			log.Errorln("evaluatePolicy: failed to get violation from", policyFile)
			return nil, errors.New("evaluatePolicy: failed to get violation from policy")
		}
		err = mapstructure.Decode(tmpInterface, &currViolations)
		if err != nil {
			log.Errorf("evaluatePolicy: failed to decode violation from %v with %v\n", policyFile, err)
			return nil, err
		}
		// Default policies only return 1 violation type per result,
		// and only 1 result for each violation type, but in case
		// custom ones don't follow this behaviour, we append instead of assign
		if currViolations.ServiceAccounts != nil && evalConfig.SaViolations {
			violations.ServiceAccounts = append(violations.ServiceAccounts, currViolations.ServiceAccounts...)
			foundViolations = true
		}
		if currViolations.Nodes != nil && evalConfig.NodeViolations {
			violations.Nodes = append(violations.Nodes, currViolations.Nodes...)
			foundViolations = true
		}
		if currViolations.Combined != nil && evalConfig.CombinedViolations {
			violations.Combined = append(violations.Combined, currViolations.Combined...)
			foundViolations = true
		}
		if currViolations.Users != nil && evalConfig.UserViolations {
			violations.Users = append(violations.Users, currViolations.Users...)
			foundViolations = true
		}
		if currViolations.Groups != nil && evalConfig.GroupViolations {
			violations.Groups = append(violations.Groups, currViolations.Groups...)
			foundViolations = true
		}
	}
	if !foundViolations {
		return nil, nil
	}
	return &violations, nil
}

// Remove identities that aren't going to be evaluated based on evalConfig
func removedUnneededIdentities(collectResult *collect.CollectResult, evalConfig EvalConfig) {
	if !evalConfig.CombinedViolations {
		if !evalConfig.SaViolations {
			collectResult.ServiceAccounts = []collect.ServiceAccountEntry{}
		}
		if !evalConfig.NodeViolations {
			collectResult.Nodes = []collect.NodeEntry{}
		}
	}
	if !evalConfig.UserViolations {
		collectResult.Users = []collect.NamedEntry{}
	}
	if !evalConfig.GroupViolations {
		collectResult.Groups = []collect.NamedEntry{}
	}
}

// Filter out serviceAccounts that aren't on all nodes
// from @collectResult
func filterOnlySasOnAllNodes(collectResult *collect.CollectResult) {
	var sasOnAllNodes []collect.ServiceAccountEntry
	nodeCount := len(collectResult.Nodes)

	for _, saEntry := range collectResult.ServiceAccounts {
		// Check if SA is on all nodes
		saNodeCount := len(saEntry.Nodes)
		if saNodeCount >= nodeCount {
			for _, node := range saEntry.Nodes {
				if node.Name == "" {
					// Ignore the empty node, which holds info on unscheduled pods
					saNodeCount -= 1
					break
				}
			}
			if saNodeCount >= nodeCount {
				sasOnAllNodes = append(sasOnAllNodes, saEntry)
			}
		}
	}
	collectResult.ServiceAccounts = sasOnAllNodes
}

// Filter out serviceAccounts in @ignoredNamespaces from @collectResult
func ignoreNamespaces(collectResult *collect.CollectResult, ignoredNamespaces []string) {
	var sasRelevantNamespaces []collect.ServiceAccountEntry

	// Remove serviceAccounts in ignored namespaces
	for _, saEntry := range collectResult.ServiceAccounts {
		ignoreSa := false
		for _, ignoredNs := range ignoredNamespaces {
			if saEntry.Namespace == ignoredNs {
				ignoreSa = true
				break
			}
		}
		if !ignoreSa {
			sasRelevantNamespaces = append(sasRelevantNamespaces, saEntry)
		}
	}
	collectResult.ServiceAccounts = sasRelevantNamespaces

	// Remove serviceAccounts in ignored namespaces from nodes
	for _, nodeEntry := range collectResult.Nodes {
		var relevantSasOnNode []string
		for _, saFullname := range nodeEntry.ServiceAccounts {
			ignoreSa := false
			for _, ignoredNs := range ignoredNamespaces {
				if strings.HasPrefix(saFullname, ignoredNs+":") {
					ignoreSa = true
				}
			}
			if !ignoreSa {
				relevantSasOnNode = append(relevantSasOnNode, saFullname)
			}
		}
		nodeEntry.ServiceAccounts = relevantSasOnNode
	}
}

// Based on filters applied to collectResult, the identities that originally referenced certain roles
// may have been removed. Purge unreferenced roles to improve policy perf.
func purgeDanglingRoles(collectResult *collect.CollectResult) {
	var referencedRoles []collect.RoleEntry
	for _, role := range collectResult.Roles {
		if roleReferencedByAnIdentity(role, collectResult) {
			referencedRoles = append(referencedRoles, role)
		}
	}
	if len(referencedRoles) < len(collectResult.Roles) {
		collectResult.Roles = referencedRoles
	}
}

// Returns whether an identity in @collectResult references the @checkedRole
func roleReferencedByAnIdentity(checkedRole collect.RoleEntry, collectResult *collect.CollectResult) bool {
	for _, sa := range collectResult.ServiceAccounts {
		for _, roleRef := range sa.Roles {
			if checkedRole.Name == roleRef.Name && checkedRole.Namespace == roleRef.Namespace {
				return true
			}
		}
	}
	for _, node := range collectResult.Nodes {
		for _, roleRef := range node.Roles {
			if checkedRole.Name == roleRef.Name && checkedRole.Namespace == roleRef.Namespace {
				return true
			}
		}
	}
	for _, user := range collectResult.Users {
		for _, roleRef := range user.Roles {
			if checkedRole.Name == roleRef.Name && checkedRole.Namespace == roleRef.Namespace {
				return true
			}
		}
	}
	for _, grp := range collectResult.Groups {
		for _, roleRef := range grp.Roles {
			if checkedRole.Name == roleRef.Name && checkedRole.Namespace == roleRef.Namespace {
				return true
			}
		}
	}
	return false
}

// Returns a shortened version of @policyResults
func AbbreviateResults(policyResults *PolicyResults) AbbreviatedPolicyResults {
	abbreviatedPolicyResults := AbbreviatedPolicyResults{
		Summary: policyResults.Summary,
	}
	for _, policyResult := range policyResults.PolicyResults {
		currAbbreviatedPolicyResult := AbbreviatedPolicyResult{
			PolicyFile:  policyResult.PolicyFile,
			Description: policyResult.Description,
			Severity:    policyResult.Severity,
		}
		currAbbreviatedPolicyResult.Violations.Nodes = policyResult.Violations.Nodes
		currAbbreviatedPolicyResult.Violations.Combined = policyResult.Violations.Combined
		currAbbreviatedPolicyResult.Violations.Users = policyResult.Violations.Users
		currAbbreviatedPolicyResult.Violations.Groups = policyResult.Violations.Groups

		// Shorten service account violations
		for _, saViolation := range policyResult.Violations.ServiceAccounts {
			saFullName := utils.FullName(saViolation.Namespace, saViolation.Name)
			currAbbreviatedPolicyResult.Violations.ServiceAccounts = append(currAbbreviatedPolicyResult.Violations.ServiceAccounts, saFullName)
		}

		abbreviatedPolicyResults.PolicyResults = append(abbreviatedPolicyResults.PolicyResults, currAbbreviatedPolicyResult)
	}

	return abbreviatedPolicyResults
}
