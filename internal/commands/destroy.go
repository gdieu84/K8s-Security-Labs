package commands

import "k8s-security-lab/internal/cluster"

func DestroyCommand(args []string) error {
	return cluster.DestroyLab()
}
