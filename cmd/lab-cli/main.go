package main

import (
	"fmt"
	"os"

	"k8s-security-lab/internal/commands"
)

func main() {

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	err := commands.Dispatch(os.Args[1:])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func printUsage() {

	fmt.Println(`
Kubernetes Security Lab CLI

Usage:
  lab-cli start           Deploy the lab environment
  lab-cli reset           Reset vulnerable scenarios
  lab-cli destroy         Remove lab namespaces
  lab-cli scan            Run security scanners
  lab-cli attack rbac     Execute RBAC escalation attack
  lab-cli attack token-request
  lab-cli attack pod-create
  lab-cli attack exec
  lab-cli attack cronjob
  lab-cli attack configmap-poison
`)
}
