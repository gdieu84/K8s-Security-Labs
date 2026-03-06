package cluster

import (
	"fmt"
	"os/exec"
)

func ApplyManifests(path string) error {

	fmt.Println("[*] Applying manifest:", path)

	cmd := exec.Command("kubectl", "apply", "-f", path)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %s", string(output))
	}

	fmt.Println(string(output))

	return nil
}
