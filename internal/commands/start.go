package commands

import "k8s-security-lab/internal/cluster"

func StartCommand(args []string) error {
	return cluster.StartLab()
}
