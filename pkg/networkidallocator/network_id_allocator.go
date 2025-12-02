package networkidallocator

import (
	"fmt"
	"maps"
	"slices"

	restate "github.com/restatedev/sdk-go"
)

type NetworkIDAllocator struct{}

const stateAllocated = "allocated"

func (n *NetworkIDAllocator) Initialize(ctx restate.ObjectContext, firstNetworkID uint64) error {
	restate.Set(ctx, "first_network_id", firstNetworkID)
	restate.Set(ctx, stateAllocated, map[string]uint64{})
	return nil
}

func (n *NetworkIDAllocator) AllocateNetworkID(ctx restate.ObjectContext, name string) (uint64, error) {
	allocatedMap, err := restate.Get[map[string]uint64](ctx, stateAllocated)
	if err != nil {
		return 0, fmt.Errorf("failed to get allocated map: %w", err)
	}

	if len(allocatedMap) == 0 {
		firstNetworkID, err := restate.Get[uint64](ctx, "first_network_id")
		if err != nil {
			return 0, fmt.Errorf("failed to get first network id: %w", err)
		}

		restate.Set(ctx, stateAllocated, map[string]uint64{name: firstNetworkID})
		return firstNetworkID, nil
	}

	{
		allocated, ok := allocatedMap[name]
		if ok {
			return allocated, nil
		}
	}

	allAllocated := slices.Collect(maps.Values(allocatedMap))

	slices.Sort(allAllocated)

	nextNetworkID := allAllocated[len(allAllocated)-1] + 1

	allocatedMap[name] = nextNetworkID

	restate.Set(ctx, stateAllocated, allocatedMap)

	return nextNetworkID, nil
}

func (n *NetworkIDAllocator) Deallocate(ctx restate.ObjectContext, name string) error {
	allocatedMap, err := restate.Get[map[string]uint64](ctx, stateAllocated)
	if err != nil {
		return fmt.Errorf("failed to get allocated map: %w", err)
	}

	delete(allocatedMap, name)

	restate.Set(ctx, stateAllocated, allocatedMap)

	return nil
}
