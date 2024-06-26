package tftp

import (
	"errors"
	"strings"
)

type command string

type argument = string

const (
	Get  command = "get"
	Dir  command = "dir"
	Put  command = "put"
	Quit command = "quit"
	Nil  command = ""
)

type Command struct {
	command
	args []argument
}

func parseCommand(s string) (command, bool) {
	switch strings.ToLower(s) {
	case "get":
		return Get, true
	case "dir":
		return Dir, true
	case "put":
		return Put, true
	case "quit":
		return Quit, true
	default:
		return Nil, false
	}
}

func readStatement(stmt string) (command, []argument, error) {
	stmt = strings.TrimSpace(stmt)
	words := strings.Fields(stmt)

	cmd, ok := parseCommand(words[0])

	if !ok {
		return "", nil, errors.New("Unrecognized command " + words[0])
	}

	return cmd, words[1:], nil
}

func readArguments(cmd command, args []argument) ([]argument, error) {
	switch cmd {
	case "dir", "quit":
		return nil, nil
	case "get", "put":
		if len(args) > 1 {
			return args[0:2], nil
		}
		return args[0:1], nil
	default:
		return nil, errors.ErrUnsupported
	}
}

func NewCommand(stmt string) (*Command, error) {
	cmd, args, err := readStatement(stmt)

	if err != nil {
		return nil, err
	}

	args, err = readArguments(cmd, args)

	return &Command{cmd, args}, err
}
