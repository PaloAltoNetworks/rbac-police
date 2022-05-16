package eval

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
)

// Get policy files with a .rego suffix under @path, ignoring directories in @ignoredDirs
func getPolicyFiles(path string, ignoredDirs map[string]struct{}) ([]string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		log.Errorf("getPolicyFiles: failed to stat(%v) with %v\n", path, err)
		return nil, err
	}

	switch mode := fileInfo.Mode(); {
	case mode.IsRegular():
		return []string{path}, nil
	case mode.IsDir():
		var policyFiles []string
		err := filepath.Walk(path+"/", // if main path is symlink, make Walk follow it
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.Mode().IsRegular() && strings.HasSuffix(path, ".rego") {
					policyFiles = append(policyFiles, path)
				}
				if info.IsDir() {
					if _, ok := ignoredDirs[info.Name()]; ok {
						return filepath.SkipDir
					}
				}
				return nil
			})
		if err != nil {
			log.Errorf("getPolicyFiles: failed to walk '%v' with %v\n", path, err)
			return nil, err
		}
		return policyFiles, nil
	}
	return nil, nil
}

// Prints results given log level is set to debug
func logResults(rs rego.ResultSet) {
	if len(rs) == 0 {
		return
	}
	for i, result := range rs {
		if len(result.Expressions) > 0 {
			log.Debugf("[+] rs[%v].Expressions:\n", i)
			for _, expression := range result.Expressions {
				log.Debugln(expression.Value)
			}
		}
	}
}
