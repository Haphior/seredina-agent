//go:build !linux && !darwin && !windows

package inventory

import "runtime"

func collect() Inventory {
	return Inventory{OSVersion: runtime.GOOS, AntivirusStatus: "unknown"}
}
