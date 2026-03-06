package commands

import "k8s-security-lab/internal/scanner"

func ScanCommand(args []string) error {
	return scanner.ScanRBAC()
}
