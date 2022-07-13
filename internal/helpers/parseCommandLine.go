package helpers

import "strconv"

// IsValidPort checks whether a provided port value can be parsed into a valid
// server port number (uint16)
func IsValidPort(port string) bool {
	_, err := strconv.ParseUint(port, 10, 16)
	return err == nil
}
