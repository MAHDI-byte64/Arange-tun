package conf

import (
	"fmt"
	"slices"
)

// Prepare applies defaults and validation to an in-memory Conf — the same steps
// LoadFromFile runs after it unmarshals YAML. It lets a caller build the Conf
// directly in Go (as the Arange-tun adapter does from its own TOML config)
// instead of writing a YAML file first.
func Prepare(c *Conf) error {
	validRoles := []string{"client", "server"}
	if !slices.Contains(validRoles, c.Role) {
		return fmt.Errorf("role must be 'client' or 'server'")
	}
	c.setDefaults()
	return c.validate()
}
