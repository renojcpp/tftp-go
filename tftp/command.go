package tftp

import (
	"errors"
	"strings"
)

type command = string
type argument = string

type Command struct {
	command
	args []argument
}

var commands = map[command]struct{}{
	"get":  {},
	"dir":  {},
	"put":  {},
	"quit": {},
}

func readStatement(stmt string) (command, []argument, error) {
	stmt = strings.TrimSpace(stmt)
	words := strings.Fields(stmt)

	_, ok := commands[words[0]]

	if !ok {
		return "", nil, errors.New("Unrecognized command " + words[0])
	}

	return words[0], words[1:], nil
}

func readArguments(cmd command, args []argument) ([]argument, error) {
	switch cmd {
	case "dir", "quit":
		return nil, nil
	case "get", "put":
		if len(args) > 2 {
			return args[0:2], errors.ErrUnsupported
		}
		return args[0:2], nil
	default:
		return nil, errors.ErrUnsupported
	}
}

func NewCommand(stmt string) (*Command, error) {
	cmd, args, err := readStatement(strings.ToLower(stmt))

	if err != nil {
		return nil, err
	}

	args, err = readArguments(cmd, args)

	return &Command{cmd, args}, err
}
