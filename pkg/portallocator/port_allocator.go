package portallocator

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	restate "github.com/restatedev/sdk-go"
)

type PortAllocator struct{}

type AllowedPorts struct {
	From uint `json:"from"`
	To   uint `json:"to"`
}

const (
	stateAllocated = "allocated"
	stateAllowed   = "allowed"
)

type allocationMap map[string]AllocatedPortRange

func (a AllowedPorts) IsAllowed(pr AllocatedPortRange) bool {
	if pr.From < a.From {
		return false
	}

	if pr.From+pr.Count > a.To {
		return false
	}

	return true
}

func (p *PortAllocator) Initialize(ctx restate.ObjectContext, allowedPorts AllowedPorts) error {
	restate.Set(ctx, stateAllowed, allowedPorts)
	restate.Set(ctx, stateAllocated, allocationMap{})
	return nil
}

type AllocatePortsParams struct {
	Count   uint   `json:"count"`
	Network string `json:"network"`
}

type AllocatedPortRange struct {
	From  uint `json:"from"`
	Count uint `json:"count"`
}

type AllocationErrorKind = string

const NO_ALLOCATABLE_RANGES AllocationErrorKind = "NO_ALLOCATABLE_RANGES"

type PortAllocationError struct {
	kind			AllocationErrorKind
	allowed 	AllowedPorts
	allocated	[]AllocatedPortRange
	count			uint
}

func (e *PortAllocationError) Error() string {
	msg := "Unknown port allocation error"

	switch e.kind {
	case NO_ALLOCATABLE_RANGES:
		msg = "Failed to find valid port range to allocate"
	}

	return msg
}

func allocate(allowedPorts AllowedPorts, allocatedPorts []AllocatedPortRange, portCount uint) (*AllocatedPortRange, error) {
	allocated := make([]AllocatedPortRange, len(allocatedPorts))
	copy(allocated, allocatedPorts)

	slices.SortFunc(allocated, func(a, b AllocatedPortRange) int {
		return int(a.From) - int(b.From)
	})

	if len(allocated) == 0 {
		newAllocated := AllocatedPortRange{
			From:  allowedPorts.From,
			Count: portCount,
		}

		if !allowedPorts.IsAllowed(newAllocated) {
			return nil, errors.New("Not enough ports available")
		}

		return &newAllocated, nil
	}

	for idx, current := range allocated[1:] {
		previous := allocated[idx]

		if current.From == previous.From {
			continue
		}

		if current.From - (previous.From + previous.Count) >= portCount {
			newAllocated := AllocatedPortRange{
				From:  previous.From + previous.Count,
				Count: portCount,
			}

			return &newAllocated, nil
		}
	}

	lastAllocated := allocated[len(allocated) - 1]

	if lastAllocated.From + lastAllocated.Count + portCount < allowedPorts.To {
		newAllocated := AllocatedPortRange{
			From: lastAllocated.From + lastAllocated.Count,
			Count: portCount,
		}

		return &newAllocated, nil
	}

	err := PortAllocationError {
		kind: NO_ALLOCATABLE_RANGES,
		allowed: allowedPorts,
		allocated: allocated,
		count: portCount,
	}
	return nil, &err
}

func (p *PortAllocator) AllocatePortRange(ctx restate.ObjectContext, params AllocatePortsParams) (*AllocatedPortRange, error) {
	allowedPortsPtr, err := restate.Get[*AllowedPorts](ctx, stateAllowed)
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed ports: %w", err)
	}
	if allowedPortsPtr == nil {
			return nil, restate.TerminalErrorf("port allocator not initialized: missing %q", stateAllowed)
	}

	allowedPorts := *allowedPortsPtr
	if allowedPorts.From == 0 && allowedPorts.To == 0 {
		return nil, fmt.Errorf("Invalid allowed port range: From=%d, To=%d", allowedPorts.From, allowedPorts.To)
	}

	allocatedPortsMapPtr, err := restate.Get[*map[string]AllocatedPortRange](ctx, stateAllocated)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated ports: %w", err)
	}
	if allocatedPortsMapPtr == nil {
		return nil, restate.TerminalErrorf("port allocator not initialized: missing %q", stateAllocated)
	}

	allocatedPortsMap := *allocatedPortsMapPtr

	{
		allocation, ok := allocatedPortsMap[params.Network]
		if ok {
			if allocation.Count != uint(params.Count) {
				return nil, restate.TerminalErrorf("already allocated port range for %s with count %d does not match requested count %d", params.Network, allocation.Count, params.Count)
			}

			return &allocation, nil
		}
	}

	allocated := slices.Collect(maps.Values(allocatedPortsMap))
	newAllocated, err := allocate(allowedPorts, allocated, params.Count)
	if err != nil {
		return nil, restate.TerminalError(err)
	}

	allocatedPortsMap[params.Network] = *newAllocated
	restate.Set(ctx, stateAllocated, allocatedPortsMap)

	return newAllocated, nil
}

func (p *PortAllocator) FreePortsForNetwork(ctx restate.ObjectContext, network string) error {
	allocatedPortsMap, err := restate.Get[allocationMap](ctx, stateAllocated)
	if err != nil {
		return fmt.Errorf("failed to get allocated ports: %w", err)
	}

	delete(allocatedPortsMap, network)

	restate.Set(ctx, stateAllocated, allocatedPortsMap)

	return nil
}
