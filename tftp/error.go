package tftp

import "fmt"

type throwErrors struct {
	actualErr error
	errorMsg  string
}

func (e *throwErrors) Error() string {
	return fmt.Sprintf("%s: %v", e.errorMsg, e.actualErr)
}
