//go:build !linux && !darwin && !windows

package network

func rawMachineID() string     { return "" }
func rawNeighbors() []Neighbor { return nil }
