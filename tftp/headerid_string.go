// Code generated by "stringer -type=HeaderId"; DO NOT EDIT.

package tftp

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[RRQ-1]
	_ = x[WRQ-2]
	_ = x[DAT-3]
	_ = x[ACK-4]
	_ = x[ERR-5]
}

const _HeaderId_name = "RRQWRQDATACKERR"

var _HeaderId_index = [...]uint8{0, 3, 6, 9, 12, 15}

func (i HeaderId) String() string {
	i -= 1
	if i >= HeaderId(len(_HeaderId_index)-1) {
		return "HeaderId(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _HeaderId_name[_HeaderId_index[i]:_HeaderId_index[i+1]]
}
