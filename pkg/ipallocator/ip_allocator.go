// Package ipallocator deals with assigning CIDR blocks to environments, and subnets within those blocks for specific networks.
package ipallocator

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	restate "github.com/restatedev/sdk-go"
)

// IPAllocator manages IP address allocation for networks and their subnets
type IPAllocator struct{}

// IPAllocatorConfig defines the global configuration for the IP allocator
type IPAllocatorConfig struct {
	// The overall IP range to allocate from (e.g., "10.0.0.0/8")
	AllowedCIDR string `json:"allowedCIDR"`
	// Default size of allocated blocks (e.g., 24 for /24 blocks)
	DefaultBlockSize int `json:"defaultBlockSize"`
	// Ranges that should be excluded from allocation
	ReservedRanges []ReservedRange `json:"reservedRanges"`
}

// ReservedRange represents an IP range that is reserved and should not be allocated
type ReservedRange struct {
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
}

// NetworkBlock represents an allocated IP block for a network
type NetworkBlock struct {
	StartIP   string `json:"startIP"`
	CIDR      string `json:"cidr"`
	BlockSize int    `json:"blockSize"`
}

type allocatedBlocks map[string]NetworkBlock

// AllocationParams defines parameters for allocating a new network block
type AllocationParams struct {
	Network string `json:"network"`
	// BlockSize represents a CIDR block, eg 24 = 256.
	BlockSize int `json:"blockSize"`
}

// SubnetAllocationParams defines parameters for allocating a subnet within a parent network
type SubnetAllocationParams struct {
	ParentNetwork string `json:"parentNetwork"`
	SubnetName    string `json:"subnetName"`
	BlockSize     int    `json:"blockSize"`
	Offset        int    `json:"offset"`
}

// AllocatorState provides a complete overview of the IP allocator configuration and current state
type AllocatorState struct {
	AllowedCIDR      string          `json:"allowedCIDR"`
	DefaultBlockSize int             `json:"defaultBlockSize"`
	ReservedRanges   []ReservedRange `json:"reservedRanges"`
	AllocatedBlocks  allocatedBlocks `json:"allocatedBlocks"`
}

// These consts serve to make it easier to use LSP to figure out where restate state is being Set/Get.
const (
	stateAllocatedBlocks = "allocated"
	stateConfig          = "config"
)

// Initialize sets up the IP allocator with a given configuration, which defines the main subnet this allocator will provide blocks for.
func (i *IPAllocator) Initialize(ctx restate.ObjectContext, config IPAllocatorConfig) error {
	allowedPrefix, err := netip.ParsePrefix(config.AllowedCIDR)
	if err != nil {
		return restate.TerminalErrorf("invalid allowed CIDR: %w", err)
	}

	for _, reserved := range config.ReservedRanges {
		reservedPrefix, err := netip.ParsePrefix(reserved.CIDR)
		if err != nil {
			return restate.TerminalErrorf("invalid reserved CIDR %s: %w", reserved.CIDR, err)
		}

		if !IsSubnetOf(reservedPrefix, allowedPrefix) {
			return restate.TerminalErrorf("reserved range %s is not within allowed range %s",
				reserved.CIDR, config.AllowedCIDR)
		}
	}

	restate.Set(ctx, stateConfig, config)
	restate.Set(ctx, stateAllocatedBlocks, allocatedBlocks{})
	return nil
}

// GetAllocatorState returns comprehensive information about the allocator configuration and current state
func (i *IPAllocator) GetAllocatorState(ctx restate.ObjectSharedContext) (*AllocatorState, error) {
	config, err := restate.Get[IPAllocatorConfig](ctx, stateConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	allocated, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated blocks: %w", err)
	}

	return &AllocatorState{
		AllowedCIDR:      config.AllowedCIDR,
		DefaultBlockSize: config.DefaultBlockSize,
		ReservedRanges:   config.ReservedRanges,
		AllocatedBlocks:  allocated,
	}, nil
}

// ResetAllocator clears all state and allows re-initialization
func (i *IPAllocator) ResetAllocator(ctx restate.ObjectContext) error {
	restate.Clear(ctx, stateConfig)
	restate.Clear(ctx, stateAllocatedBlocks)

	ctx.Log().Info("Reset allocator state")
	return nil
}

// AllocateNetworkBlock allocates a new block within the main subnet for a specific network.
// If the network already has an allocation, returns the existing allocation.
func (i *IPAllocator) AllocateNetworkBlock(ctx restate.ObjectContext, params AllocationParams) (*NetworkBlock, error) {
	config, err := restate.Get[IPAllocatorConfig](ctx, stateConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated network blocks: %w", err)
	}

	if allocation, ok := allocatedMap[params.Network]; ok {
		if params.BlockSize != 0 && allocation.BlockSize != params.BlockSize {
			return nil, restate.TerminalErrorf("network %s already has allocation with block size /%d, requested /%d",
				params.Network, allocation.BlockSize, params.BlockSize)
		}
		return &allocation, nil
	}

	blockSize := params.BlockSize
	if blockSize == 0 {
		blockSize = config.DefaultBlockSize
	}

	allowedPrefix, err := netip.ParsePrefix(config.AllowedCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowed CIDR: %w", err)
	}

	if blockSizeEscapesCIDR(blockSize, allowedPrefix) {
		return nil, restate.TerminalErrorf("requested block size /%d is larger than allowed block /%d",
			blockSize, allowedPrefix.Bits())
	}

	allocated := slices.Collect(maps.Values(allocatedMap))
	slices.SortFunc(allocated, func(a, b NetworkBlock) int {
		aIP, _ := netip.ParseAddr(a.StartIP)
		bIP, _ := netip.ParseAddr(b.StartIP)
		return aIP.Compare(bIP)
	})

	nextIP, err := FindNextAvailableBlock(allowedPrefix, allocated, config.ReservedRanges, blockSize)
	if err != nil {
		return nil, restate.TerminalErrorf("failed to find available block: %v", err)
	}
	if !nextIP.IsValid() {
		return nil, restate.TerminalErrorf("no available IP blocks of size /%d", blockSize)
	}

	newAllocation := NetworkBlock{
		StartIP:   nextIP.String(),
		CIDR:      fmt.Sprintf("%s/%d", nextIP.String(), blockSize),
		BlockSize: blockSize,
	}

	allocatedMap[params.Network] = newAllocation
	restate.Set(ctx, stateAllocatedBlocks, allocatedMap)

	return &newAllocation, nil
}

// AllocateSubnetBlock allocates a subnet within an existing network block
// The subnet will be named "parentNetwork-subnetName" and must have a larger
// prefix size than its parent network
func (i *IPAllocator) AllocateSubnetBlock(ctx restate.ObjectContext, params SubnetAllocationParams) (*NetworkBlock, error) {
	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated network blocks: %w", err)
	}

	parentBlock, exists := allocatedMap[params.ParentNetwork]
	if !exists {
		return nil, fmt.Errorf("parent network %s does not exist", params.ParentNetwork)
	}

	parentPrefix, err := netip.ParsePrefix(parentBlock.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid parent CIDR: %w", err)
	}

	if params.BlockSize <= parentBlock.BlockSize {
		return nil, fmt.Errorf("requested subnet size /%d must be larger than parent network size /%d",
			params.BlockSize, parentBlock.BlockSize)
	}

	subnetName := params.SubnetName
	if subnetName == "" {
		subnetName = fmt.Sprintf("subnet-%d", params.BlockSize)
	}
	fullSubnetName := fmt.Sprintf("%s-%s", params.ParentNetwork, subnetName)

	if existingSubnet, ok := allocatedMap[fullSubnetName]; ok {
		if params.BlockSize != existingSubnet.BlockSize {
			return nil, restate.TerminalErrorf(
				"subnet %s already exists with block size /%d, requested /%d",
				fullSubnetName, existingSubnet.BlockSize, params.BlockSize)
		}
		return &existingSubnet, nil
	}

	subnetBits := params.BlockSize - parentBlock.BlockSize
	if subnetBits <= 0 {
		return nil, fmt.Errorf("invalid subnet size: must be smaller than parent network")
	}

	maxSubnets := 1 << subnetBits
	if params.Offset >= maxSubnets {
		return nil, restate.TerminalErrorf("offset %d exceeds maximum possible subnets (%d) for this network/size combination",
			params.Offset, maxSubnets)
	}

	parentAddr := parentPrefix.Addr()
	parentAddrInt, err := IPToUint32(parentAddr)
	if err != nil {
		return nil, restate.TerminalErrorf("failed to convert parent address to integer: %w", err)
	}

	subnetSize := 1 << (32 - params.BlockSize)
	subnetAddrInt := parentAddrInt + uint32(params.Offset*subnetSize)
	subnetAddr := Uint32ToIP(subnetAddrInt)

	subnetPrefix := netip.PrefixFrom(subnetAddr, params.BlockSize)

	if !IsSubnetOf(subnetPrefix, parentPrefix) {
		return nil, restate.TerminalErrorf("calculated subnet %s is not within parent network %s",
			subnetPrefix.String(), parentBlock.CIDR)
	}

	subnetBlock := NetworkBlock{
		StartIP:   subnetAddr.String(),
		CIDR:      subnetPrefix.String(),
		BlockSize: params.BlockSize,
	}

	allocatedMap[fullSubnetName] = subnetBlock
	restate.Set(ctx, stateAllocatedBlocks, allocatedMap)

	ctx.Log().Info("Allocated subnet",
		"parentNetwork", params.ParentNetwork,
		"subnetName", fullSubnetName,
		"cidr", subnetBlock.CIDR)

	return &subnetBlock, nil
}

// ReleaseSubnetBlock releases a specific subnet without affecting its parent network
func (i *IPAllocator) ReleaseSubnetBlock(ctx restate.ObjectContext, params struct {
	ParentNetwork string `json:"parentNetwork"`
	SubnetName    string `json:"subnetName"`
},
) error {
	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return fmt.Errorf("failed to get allocated network blocks: %w", err)
	}

	fullSubnetName := fmt.Sprintf("%s-%s", params.ParentNetwork, params.SubnetName)

	subnet, exists := allocatedMap[fullSubnetName]
	if !exists {
		ctx.Log().Warn("Attempting to release non-existent subnet",
			"subnet", fullSubnetName,
			"parentNetwork", params.ParentNetwork)
		return nil
	}

	// Check if parent network exists
	_, parentExists := allocatedMap[params.ParentNetwork]
	if !parentExists {
		ctx.Log().Warn("Parent network does not exist but subnet does",
			"subnet", fullSubnetName,
			"parentNetwork", params.ParentNetwork)
	}

	delete(allocatedMap, fullSubnetName)
	restate.Set(ctx, stateAllocatedBlocks, allocatedMap)

	ctx.Log().Info("Released subnet",
		"subnet", fullSubnetName,
		"parentNetwork", params.ParentNetwork,
		"cidr", subnet.CIDR)

	return nil
}

// ReleaseNetworkBlock removes a network block allocation and any of its subnets
func (i *IPAllocator) ReleaseNetworkBlock(ctx restate.ObjectContext, network string) error {
	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return fmt.Errorf("failed to get allocated network blocks: %w", err)
	}

	if _, exists := allocatedMap[network]; !exists {
		ctx.Log().Warn("Attempting to release non-existent network block", "network", network)
		return nil
	}

	for subnetName := range allocatedMap {
		if IsSubnetNameOf(subnetName, network) {
			ctx.Log().Info("Auto-releasing subnet", "subnet", subnetName, "parent", network)
			delete(allocatedMap, subnetName)
		}
	}

	delete(allocatedMap, network)
	restate.Set(ctx, stateAllocatedBlocks, allocatedMap)

	ctx.Log().Info("Released network block", "network", network)
	return nil
}

// GetAllocatedBlocks returns all allocated network blocks
func (i *IPAllocator) GetAllocatedBlocks(ctx restate.ObjectSharedContext) (allocatedBlocks, error) {
	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated network blocks: %w", err)
	}
	return allocatedMap, nil
}

// GetReservedRanges returns the reserved ranges from configuration
func (i *IPAllocator) GetReservedRanges(ctx restate.ObjectSharedContext) ([]ReservedRange, error) {
	config, err := restate.Get[IPAllocatorConfig](ctx, stateConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	return config.ReservedRanges, nil
}

// HasNetworkBlock checks if a network has an IP allocation
func (i *IPAllocator) HasNetworkBlock(ctx restate.ObjectSharedContext, network string) (bool, error) {
	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return false, fmt.Errorf("failed to get allocated network blocks: %w", err)
	}

	_, exists := allocatedMap[network]
	return exists, nil
}

// GetNetworkBlock returns a specific network's allocation
func (i *IPAllocator) GetNetworkBlock(ctx restate.ObjectSharedContext, network string) (*NetworkBlock, error) {
	allocatedMap, err := restate.Get[allocatedBlocks](ctx, stateAllocatedBlocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocated network blocks: %w", err)
	}

	block, exists := allocatedMap[network]
	if !exists {
		return nil, fmt.Errorf("no allocation found for network %s", network)
	}

	return &block, nil
}
