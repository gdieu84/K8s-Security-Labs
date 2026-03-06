package commands

import "k8s-security-lab/internal/cluster"

func ResetCommand(args []string) error {
	return cluster.ResetLab()
}
