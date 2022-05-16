package utils

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

// Reads file a @path
func ReadFile(path string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Errorf("ReadFile: failed reading '%v' with: %v\n", path, err)
		return nil, err
	}
	return bytes, nil
}

// Get the full name of a namespaced k8s object
func FullName(namespace string, name string) string {
	return namespace + ":" + name
}
