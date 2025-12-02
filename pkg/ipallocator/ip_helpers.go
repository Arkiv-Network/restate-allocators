package ipallocator

import (
	"fmt"
	"net"
	"net/netip"

	"go4.org/netipx"
)

// GetFirstUsableIP returns the first usable IP in a subnet (excludes network address)
func GetFirstUsableIP(prefix netip.Prefix) netip.Addr {
	return prefix.Addr().Next()
}

// GetLastUsableIP returns the last usable IP in a subnet (excludes broadcast address)
func GetLastUsableIP(prefix netip.Prefix) netip.Addr {
	return netipx.PrefixLastIP(prefix).Prev()
}

// GetGatewayIP typically returns the first usable IP as the gateway
func GetGatewayIP(prefix netip.Prefix) netip.Addr {
	return GetFirstUsableIP(prefix)
}

// GetSubnetSize returns the total number of IPs in a subnet
func GetSubnetSize(prefix netip.Prefix) int {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		return 1 << (32 - bits)
	}
	// For IPv6, limit to reasonable size
	if prefix.Addr().Is6() && (128-bits) >= 16 {
		return 1 << 16
	}
	return 1 << (128 - bits)
}

// GetUsableIPCount returns the number of usable IPs (excluding network and broadcast)
func GetUsableIPCount(prefix netip.Prefix) int {
	size := GetSubnetSize(prefix)
	if size <= 2 {
		return 0
	}
	return size - 2
}

// IPRangeInfo provides detailed information about an IP range
type IPRangeInfo struct {
	Network     string `json:"network"`
	Netmask     string `json:"netmask"`
	Gateway     string `json:"gateway"`
	Broadcast   string `json:"broadcast"`
	FirstUsable string `json:"firstUsable"`
	LastUsable  string `json:"lastUsable"`
	TotalIPs    int    `json:"totalIPs"`
	UsableIPs   int    `json:"usableIPs"`
}

// GetIPRangeInfo returns detailed information about an IP range
func GetIPRangeInfo(cidr string) (*IPRangeInfo, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Currently only supporting IPv4
	if prefix.Addr().Is6() {
		return nil, fmt.Errorf("IPv6 is not currently supported for range info")
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR: %w", err)
	}

	info := &IPRangeInfo{
		Network:     prefix.Addr().String(),
		Netmask:     net.IP(ipnet.Mask).String(),
		Gateway:     GetGatewayIP(prefix).String(),
		Broadcast:   netipx.PrefixLastIP(prefix).String(),
		FirstUsable: GetFirstUsableIP(prefix).String(),
		LastUsable:  GetLastUsableIP(prefix).String(),
		TotalIPs:    GetSubnetSize(prefix),
		UsableIPs:   GetUsableIPCount(prefix),
	}

	return info, nil
}

// GetNextIP returns the next IP address after the given IP
func GetNextIP(ip netip.Addr) netip.Addr {
	return ip.Next()
}

// GetNextNIPs returns the next n IP addresses after the given IP
func GetNextNIPs(startIP netip.Addr, n int) ([]netip.Addr, error) {
	if !startIP.IsValid() {
		return nil, fmt.Errorf("invalid IP address")
	}

	// Currently only supporting IPv4
	if startIP.Is6() {
		return nil, fmt.Errorf("IPv6 is not currently supported for this operation")
	}

	result := make([]netip.Addr, n)
	currentIP := startIP

	for i := range n {
		currentIP = currentIP.Next()
		if !currentIP.IsValid() {
			return nil, fmt.Errorf("reached invalid IP after %d iterations", i)
		}
		result[i] = currentIP
	}

	return result, nil
}

// IsSubnetOf checks if subnet is contained within parent prefix
func IsSubnetOf(subnet, parent netip.Prefix) bool {
	// First check if the subnet prefix length is >= parent prefix length
	if subnet.Bits() < parent.Bits() {
		return false
	}

	// Check if both are the same IP version
	if subnet.Addr().Is4() != parent.Addr().Is4() {
		return false // Different IP versions can't be subnets of each other
	}

	// Check if the subnet is fully contained in the parent by checking if:
	// 1. The parent contains the first IP of the subnet
	// 2. The parent contains the last IP of the subnet
	return parent.Contains(subnet.Addr()) && parent.Contains(netipx.PrefixLastIP(subnet))
}

func blockSizeEscapesCIDR(blockSize int, p netip.Prefix) bool {
	return blockSize < p.Bits()
}

// RangesOverlap checks if two IP ranges overlap
func RangesOverlap(r1, r2 netipx.IPRange) bool {
	// Two ranges overlap if one contains any endpoint of the other
	return r1.Contains(r2.From()) || r1.Contains(r2.To()) ||
		r2.Contains(r1.From()) || r2.Contains(r1.To())
}

// AlignToBlockBoundary aligns an IP address to the block boundary for the given block size
func AlignToBlockBoundary(addr netip.Addr, blockSize int) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}

	if addr.Is6() {
		return netip.Addr{}, fmt.Errorf("IPv6 is not currently supported for block alignment")
	}

	if blockSize < 0 || blockSize > 32 {
		return netip.Addr{}, fmt.Errorf("invalid block size for IPv4: %d", blockSize)
	}

	return netip.PrefixFrom(addr, blockSize).Masked().Addr(), nil
}

// IPToUint32 converts an IPv4 address to a uint32 integer
func IPToUint32(ip netip.Addr) (uint32, error) {
	if !ip.IsValid() {
		return 0, fmt.Errorf("invalid IP address")
	}

	if !ip.Is4() {
		return 0, fmt.Errorf("IPv6 addresses cannot be converted to uint32")
	}

	bytes := ip.AsSlice()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]), nil
}

// Uint32ToIP converts a uint32 integer to an IPv4 address
func Uint32ToIP(n uint32) netip.Addr {
	bytes := [4]byte{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
	return netip.AddrFrom4(bytes)
}

// IsSubnetNameOf determines if a subnet name belongs to a parent network
func IsSubnetNameOf(subnetName, parentName string) bool {
	return len(subnetName) > len(parentName)+1 &&
		subnetName[:len(parentName)] == parentName &&
		subnetName[len(parentName)] == '-'
}

// FindNextAvailableBlock locates the next available IP block of the requested size
func FindNextAvailableBlock(allowedPrefix netip.Prefix, allocated []NetworkBlock, reserved []ReservedRange, blockSize int) (netip.Addr, error) {
	if allowedPrefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("IPv6 is not currently supported for block allocation")
	}

	if blockSize < 0 || blockSize > 32 {
		return netip.Addr{}, fmt.Errorf("invalid block size for IPv4: %d", blockSize)
	}

	// Returns first IP in block.
	alignedAddr, err := AlignToBlockBoundary(allowedPrefix.Addr(), blockSize)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to align address: %w", err)
	}

	currentAddr := alignedAddr
	if !currentAddr.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid aligned address")
	}

	var builder netipx.IPSetBuilder

	for _, r := range reserved {
		reservedPrefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid reserved CIDR %s: %w", r.CIDR, err)
		}
		builder.AddPrefix(reservedPrefix)
	}

	for _, a := range allocated {
		allocPrefix, err := netip.ParsePrefix(a.CIDR)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid allocated CIDR %s: %w", a.CIDR, err)
		}
		builder.AddPrefix(allocPrefix)
	}

	occupiedSet, err := builder.IPSet()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to build IP set: %w", err)
	}

	occupiedRanges := occupiedSet.Ranges()

	for allowedPrefix.Contains(currentAddr) {
		proposedPrefix := netip.PrefixFrom(currentAddr, blockSize)
		proposedEnd := netipx.PrefixLastIP(proposedPrefix)

		if !allowedPrefix.Contains(proposedEnd) {
			return netip.Addr{}, fmt.Errorf("no available blocks of size /%d within allowed range", blockSize)
		}

		overlaps := false
		proposedRange := netipx.IPRangeFrom(currentAddr, proposedEnd)

		for _, occupied := range occupiedRanges {
			if RangesOverlap(proposedRange, occupied) {
				overlaps = true
				nextAddr := occupied.To().Next()
				if !nextAddr.IsValid() || !allowedPrefix.Contains(nextAddr) {
					return netip.Addr{}, fmt.Errorf("no available address after occupied range")
				}

				alignedNext, err := AlignToBlockBoundary(nextAddr, blockSize)
				if err != nil {
					return netip.Addr{}, fmt.Errorf("failed to align next address: %w", err)
				}

				currentAddr = alignedNext
				if !currentAddr.IsValid() {
					return netip.Addr{}, fmt.Errorf("invalid aligned next address")
				}
				break
			}
		}

		if !overlaps {
			return currentAddr, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no available blocks of size /%d found in allowed range", blockSize)
}
