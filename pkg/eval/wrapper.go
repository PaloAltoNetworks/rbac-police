package eval

import (
	"regexp"
)

const (
	wrapperFileSuffix = "utils/wrapper.rego" // TODO: move elsewhere / make configurable / go-bindata
)

var (
	wrapperFilePath string
	wrappedPattern  = `(?m)^\s*main\s*\[\s*\{.*\}\s*\].*$`
)

// Checks if policy needs wrapping (doesn't define main rule)
func policyNeedsWrapping(policy string) bool {
	isWrapped, _ := regexp.MatchString(wrappedPattern, policy)
	return !isWrapped // needs wrapping
}
