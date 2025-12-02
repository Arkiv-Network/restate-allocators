package portallocator

import (
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

func (p *PortAllocator) AllocatePortRange(ctx restate.ObjectContext, params AllocatePortsParams) (*AllocatedPortRange, error) {
	allowedPorts, err := restate.Get[AllowedPorts](ctx, stateAllowed)
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed ports: %w", err)
	}

	allocatedPortsMap, err := restate.Get[map[string]AllocatedPortRange](ctx, stateAllocated)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated ports: %w", err)
	}

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

	slices.SortFunc(allocated, func(a, b AllocatedPortRange) int {
		return int(a.From) - int(b.From)
	})

	if len(allocated) == 0 {
		newAllocated := AllocatedPortRange{
			From:  allowedPorts.From,
			Count: uint(params.Count),
		}

		if !allowedPorts.IsAllowed(newAllocated) {
			return nil, restate.TerminalErrorf("not enough ports available")
		}

		allocatedPortsMap[params.Network] = newAllocated

		restate.Set(ctx, stateAllocated, allocatedPortsMap)

		return &newAllocated, nil
	}

	prevAllocated := allocated[0]

	if (prevAllocated.From - allowedPorts.From) >= uint(params.Count) {
		newAllocated := AllocatedPortRange{
			From:  allowedPorts.From,
			Count: uint(params.Count),
		}

		allocatedPortsMap[params.Network] = newAllocated

		restate.Set(ctx, stateAllocated, allocatedPortsMap)

		return &newAllocated, nil
	}

	for _, allocatedPort := range allocated[1:] {
		if allocatedPort.From-(prevAllocated.From+prevAllocated.Count) >= uint(params.Count) {
			newAllocated := AllocatedPortRange{
				From:  prevAllocated.From + prevAllocated.Count,
				Count: uint(params.Count),
			}

			allocatedPortsMap[params.Network] = newAllocated

			restate.Set(ctx, stateAllocated, allocatedPortsMap)

			return &newAllocated, nil
		}
	}

	lastAllocated := allocated[len(allocated)-1]

	newAllocated := AllocatedPortRange{
		From:  lastAllocated.From + lastAllocated.Count,
		Count: uint(params.Count),
	}

	if !allowedPorts.IsAllowed(newAllocated) {
		return nil, restate.TerminalErrorf("not enoughports available")
	}

	allocatedPortsMap[params.Network] = newAllocated

	restate.Set(ctx, stateAllocated, allocatedPortsMap)

	return &newAllocated, nil
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
