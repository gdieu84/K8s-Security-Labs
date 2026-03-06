package commands

import (
	"fmt"
	"k8s-security-lab/internal/scenarios"
)

func AttackCommand(args []string) error {

	if len(args) == 0 {
		return fmt.Errorf("missing attack scenario")
	}

	switch args[0] {

	case "rbac":
		return scenarios.RBACAttack()

	case "token":
		return scenarios.TokenAttack()

	case "token-request":
		return scenarios.TokenRequestAttack()

	case "cronjob":
		return scenarios.CronJobAttack()

	case "configmap-poison":
		return scenarios.ConfigMapPoisonAttack()

	case "escape":
		return scenarios.EscapeAttack()

	case "exec":
		return scenarios.ExecAttack()

	case "lateral":
		return scenarios.LateralAttack()

	case "pod-create":
		return scenarios.PodCreateAttack()

	case "secrets":
		return scenarios.SecretsAttack()

	default:
		return fmt.Errorf("unknown attack scenario: %s", args[0])
	}
}
