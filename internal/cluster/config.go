package cluster

import (
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func GetConfig() (*rest.Config, error) {
	return config.GetConfig()
}
