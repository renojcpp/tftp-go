package tftp

import "fmt"

type throwErrors struct {
	actualErr error
	errorMsg  string
}

func (e *throwErrors) Error() string {
	return fmt.Sprintf("Error Occurred: %s, %v", e.errorMsg, e.actualErr)
}
