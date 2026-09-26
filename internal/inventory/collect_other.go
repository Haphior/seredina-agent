//go:build !linux && !darwin && !windows

package inventory

import "runtime"

func collect() Details {
	d := Details{Network: goInterfaces(), VirtualMachines: containerGuests()}
	d.OS.Name = runtime.GOOS
	d.OS.Arch = runtimeArch()
	d.System.Timezone = unixTimezone()
	d.legacyAV = "unknown"
	return d
}
