package commands

import (
	"fmt"
)

type CommandFunc func(args []string) error

var commandRegistry = map[string]CommandFunc{
	"start":   StartCommand,
	"reset":   ResetCommand,
	"destroy": DestroyCommand,
	"scan":    ScanCommand,
	"attack":  AttackCommand,
}

func Dispatch(args []string) error {

	if len(args) == 0 {
		return fmt.Errorf("no command provided")
	}

	cmd := args[0]

	handler, exists := commandRegistry[cmd]
	if !exists {
		return fmt.Errorf("unknown command: %s", cmd)
	}

	return handler(args[1:])
}
