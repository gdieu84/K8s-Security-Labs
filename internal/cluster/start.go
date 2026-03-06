package cluster

import "fmt"

func StartLab() error {

	fmt.Println("[*] Initializing Kubernetes Security Lab")

	fmt.Println("[*] Creating namespaces")

	CreateNamespace("tenant-a")
	CreateNamespace("tenant-b")

	fmt.Println("[*] Creating ServiceAccounts")

	err := CreateTenantServiceAccount("tenant-a")
	if err != nil {
		return err
	}

	fmt.Println("[*] Deploying vulnerable RBAC")

	err = DeployVulnerableRBAC()
	if err != nil {
		return err
	}

	err = DeployVulnerableSecret()
	if err != nil {
		return err
	}

	fmt.Println("[+] Lab successfully deployed")

	return nil
}
