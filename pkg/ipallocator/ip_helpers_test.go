package ipallocator

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

func TestGetFirstUsableIP(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected string
	}{
		{
			name:     "IPv4 /24 subnet",
			cidr:     "192.168.1.0/24",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 /32 host address",
			cidr:     "10.0.0.1/32",
			expected: "10.0.0.2",
		},
		{
			name:     "IPv4 /16 large subnet",
			cidr:     "172.16.0.0/16",
			expected: "172.16.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.cidr)
			require.NoError(t, err)

			result := GetFirstUsableIP(prefix)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

func TestGetLastUsableIP(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected string
	}{
		{
			name:     "IPv4 /24 subnet",
			cidr:     "192.168.1.0/24",
			expected: "192.168.1.254",
		},
		{
			name:     "IPv4 /30 small subnet",
			cidr:     "10.0.0.0/30",
			expected: "10.0.0.2",
		},
		{
			name:     "IPv4 /32 host address",
			cidr:     "10.0.0.1/32",
			expected: "10.0.0.0", // .prev() on last IP (which is itself)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.cidr)
			require.NoError(t, err)

			result := GetLastUsableIP(prefix)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

func TestGetGatewayIP(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected string
	}{
		{
			name:     "IPv4 /24 subnet",
			cidr:     "192.168.1.0/24",
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.cidr)
			require.NoError(t, err)

			result := GetGatewayIP(prefix)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

func TestGetSubnetSize(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected int
	}{
		{
			name:     "IPv4 /24 subnet",
			cidr:     "192.168.1.0/24",
			expected: 256,
		},
		{
			name:     "IPv4 /30 small subnet",
			cidr:     "10.0.0.0/30",
			expected: 4,
		},
		{
			name:     "IPv4 /32 host address",
			cidr:     "10.0.0.1/32",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.cidr)
			require.NoError(t, err)

			result := GetSubnetSize(prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetUsableIPCount(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected int
	}{
		{
			name:     "IPv4 /24 subnet",
			cidr:     "192.168.1.0/24",
			expected: 254,
		},
		{
			name:     "IPv4 /30 small subnet",
			cidr:     "10.0.0.0/30",
			expected: 2,
		},
		{
			name:     "IPv4 /31 point-to-point",
			cidr:     "10.0.0.0/31",
			expected: 0,
		},
		{
			name:     "IPv4 /32 host address",
			cidr:     "10.0.0.1/32",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.cidr)
			require.NoError(t, err)

			result := GetUsableIPCount(prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetIPRangeInfo(t *testing.T) {
	tests := []struct {
		name          string
		cidr          string
		expectError   bool
		expectedInfo  *IPRangeInfo
		errorContains string
	}{
		{
			name:        "Valid IPv4 /24 network",
			cidr:        "192.168.1.0/24",
			expectError: false,
			expectedInfo: &IPRangeInfo{
				Network:     "192.168.1.0",
				Netmask:     "255.255.255.0",
				Gateway:     "192.168.1.1",
				Broadcast:   "192.168.1.255",
				FirstUsable: "192.168.1.1",
				LastUsable:  "192.168.1.254",
				TotalIPs:    256,
				UsableIPs:   254,
			},
		},
		{
			name:        "Valid IPv4 /28 network",
			cidr:        "10.0.0.16/28",
			expectError: false,
			expectedInfo: &IPRangeInfo{
				Network:     "10.0.0.16",
				Netmask:     "255.255.255.240",
				Gateway:     "10.0.0.17",
				Broadcast:   "10.0.0.31",
				FirstUsable: "10.0.0.17",
				LastUsable:  "10.0.0.30",
				TotalIPs:    16,
				UsableIPs:   14,
			},
		},
		{
			name:          "Invalid CIDR",
			cidr:          "invalid-cidr",
			expectError:   true,
			errorContains: "invalid CIDR",
		},
		{
			name:          "IPv6 network (not supported)",
			cidr:          "2001:db8::/64",
			expectError:   true,
			errorContains: "IPv6 is not currently supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetIPRangeInfo(tt.cidr)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedInfo.Network, info.Network)
			assert.Equal(t, tt.expectedInfo.Netmask, info.Netmask)
			assert.Equal(t, tt.expectedInfo.Gateway, info.Gateway)
			assert.Equal(t, tt.expectedInfo.Broadcast, info.Broadcast)
			assert.Equal(t, tt.expectedInfo.FirstUsable, info.FirstUsable)
			assert.Equal(t, tt.expectedInfo.LastUsable, info.LastUsable)
			assert.Equal(t, tt.expectedInfo.TotalIPs, info.TotalIPs)
			assert.Equal(t, tt.expectedInfo.UsableIPs, info.UsableIPs)
		})
	}
}

func TestGetNextNIPs(t *testing.T) {
	tests := []struct {
		name          string
		startIP       string
		n             int
		expected      []string
		expectError   bool
		errorContains string
	}{
		{
			name:     "Get next 3 IPs after 192.168.1.10",
			startIP:  "192.168.1.10",
			n:        3,
			expected: []string{"192.168.1.11", "192.168.1.12", "192.168.1.13"},
		},
		{
			name:     "Get next 1 IP after 10.0.0.255",
			startIP:  "10.0.0.255",
			n:        1,
			expected: []string{"10.0.1.0"},
		},
		{
			name:          "Invalid IP",
			startIP:       "invalid-ip",
			n:             3,
			expectError:   true,
			errorContains: "invalid IP",
		},
		{
			name:          "IPv6 address (not supported)",
			startIP:       "2001:db8::1",
			n:             3,
			expectError:   true,
			errorContains: "IPv6 is not currently supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var startIP netip.Addr
			var err error

			if !tt.expectError || tt.errorContains != "invalid IP" {
				startIP, err = netip.ParseAddr(tt.startIP)
				require.NoError(t, err)
			} else {
				startIP = netip.Addr{} // Invalid address
			}

			results, err := GetNextNIPs(startIP, tt.n)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.n, len(results))

			for i, expected := range tt.expected {
				assert.Equal(t, expected, results[i].String())
			}
		})
	}
}

func TestIsSubnetOf(t *testing.T) {
	tests := []struct {
		name     string
		subnet   string
		parent   string
		expected bool
	}{
		{
			name:     "subnet is within parent",
			subnet:   "10.43.200.0/24",
			parent:   "10.43.0.0/16",
			expected: true,
		},
		{
			name:     "subnet equals parent",
			subnet:   "10.43.0.0/16",
			parent:   "10.43.0.0/16",
			expected: true,
		},
		{
			name:     "subnet is larger than parent",
			subnet:   "10.0.0.0/8",
			parent:   "10.43.0.0/16",
			expected: false,
		},
		{
			name:     "subnet is outside parent",
			subnet:   "192.168.0.0/24",
			parent:   "10.43.0.0/16",
			expected: false,
		},
		{
			name:     "subnet partially overlaps parent",
			subnet:   "10.42.0.0/15",
			parent:   "10.43.0.0/16",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet, err := netip.ParsePrefix(tt.subnet)
			require.NoError(t, err)
			parent, err := netip.ParsePrefix(tt.parent)
			require.NoError(t, err)

			result := IsSubnetOf(subnet, parent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRangesOverlap(t *testing.T) {
	tests := []struct {
		name     string
		range1   string
		range2   string
		expected bool
	}{
		{
			name:     "ranges overlap completely",
			range1:   "192.168.1.0-192.168.1.255",
			range2:   "192.168.1.0-192.168.1.255",
			expected: true,
		},
		{
			name:     "range1 contains range2",
			range1:   "192.168.1.0-192.168.1.255",
			range2:   "192.168.1.100-192.168.1.200",
			expected: true,
		},
		{
			name:     "range2 contains range1",
			range1:   "192.168.1.100-192.168.1.200",
			range2:   "192.168.1.0-192.168.1.255",
			expected: true,
		},
		{
			name:     "ranges overlap partially",
			range1:   "192.168.1.0-192.168.1.150",
			range2:   "192.168.1.100-192.168.1.255",
			expected: true,
		},
		{
			name:     "ranges don't overlap",
			range1:   "192.168.1.0-192.168.1.100",
			range2:   "192.168.1.150-192.168.1.255",
			expected: false,
		},
		{
			name:     "ranges adjacent but don't overlap",
			range1:   "192.168.1.0-192.168.1.100",
			range2:   "192.168.1.101-192.168.1.200",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseRange := func(r string) netipx.IPRange {
				parts := splitRange(t, r)
				from, err := netip.ParseAddr(parts[0])
				require.NoError(t, err)
				to, err := netip.ParseAddr(parts[1])
				require.NoError(t, err)
				return netipx.IPRangeFrom(from, to)
			}

			range1 := parseRange(tt.range1)
			range2 := parseRange(tt.range2)

			result := RangesOverlap(range1, range2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAlignToBlockBoundary(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		blockSize     int
		expected      string
		expectError   bool
		errorContains string
	}{
		{
			name:      "Align 192.168.1.43 to /24",
			ip:        "192.168.1.43",
			blockSize: 24,
			expected:  "192.168.1.0",
		},
		{
			name:      "Align 10.10.10.10 to /16",
			ip:        "10.10.10.10",
			blockSize: 16,
			expected:  "10.10.0.0",
		},
		{
			name:      "Align 172.16.5.1 to /20",
			ip:        "172.16.5.1",
			blockSize: 20,
			expected:  "172.16.0.0",
		},
		{
			name:          "IPv6 address (not supported)",
			ip:            "2001:db8::1",
			blockSize:     64,
			expectError:   true,
			errorContains: "IPv6 is not currently supported",
		},
		{
			name:          "Invalid block size (too large)",
			ip:            "192.168.1.1",
			blockSize:     33,
			expectError:   true,
			errorContains: "invalid block size",
		},
		{
			name:          "Invalid block size (negative)",
			ip:            "192.168.1.1",
			blockSize:     -1,
			expectError:   true,
			errorContains: "invalid block size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.ip)
			require.NoError(t, err)

			result, err := AlignToBlockBoundary(addr, tt.blockSize)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		expected      uint32
		expectError   bool
		errorContains string
	}{
		{
			name:     "Convert 192.168.1.1",
			ip:       "192.168.1.1",
			expected: 3232235777, // 192*2^24 + 168*2^16 + 1*2^8 + 1
		},
		{
			name:     "Convert 10.0.0.1",
			ip:       "10.0.0.1",
			expected: 167772161, // 10*2^24 + 0*2^16 + 0*2^8 + 1
		},
		{
			name:     "Convert 255.255.255.255",
			ip:       "255.255.255.255",
			expected: 4294967295, // 2^32 - 1
		},
		{
			name:          "IPv6 address (not supported)",
			ip:            "2001:db8::1",
			expectError:   true,
			errorContains: "IPv6 addresses cannot be converted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.ip)
			require.NoError(t, err)

			result, err := IPToUint32(addr)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name     string
		n        uint32
		expected string
	}{
		{
			name:     "Convert 3232235777 to 192.168.1.1",
			n:        3232235777,
			expected: "192.168.1.1",
		},
		{
			name:     "Convert 167772161 to 10.0.0.1",
			n:        167772161,
			expected: "10.0.0.1",
		},
		{
			name:     "Convert 4294967295 to 255.255.255.255",
			n:        4294967295,
			expected: "255.255.255.255",
		},
		{
			name:     "Convert 0 to 0.0.0.0",
			n:        0,
			expected: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Uint32ToIP(tt.n)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

func TestIsSubnetNameOf(t *testing.T) {
	tests := []struct {
		name       string
		subnetName string
		parentName string
		expected   bool
	}{
		{
			name:       "Valid subnet name",
			subnetName: "network1-subnet1",
			parentName: "network1",
			expected:   true,
		},
		{
			name:       "Another valid subnet name",
			subnetName: "network1-sequencers",
			parentName: "network1",
			expected:   true,
		},
		{
			name:       "Same name",
			subnetName: "network1",
			parentName: "network1",
			expected:   false,
		},
		{
			name:       "Different parent network",
			subnetName: "network2-subnet",
			parentName: "network1",
			expected:   false,
		},
		{
			name:       "Parent as prefix but not complete name",
			subnetName: "network1extendedname-subnet",
			parentName: "network1",
			expected:   false,
		},
		{
			name:       "Parent as suffix",
			subnetName: "prefix-network1",
			parentName: "network1",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSubnetNameOf(tt.subnetName, tt.parentName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindNextAvailableBlock(t *testing.T) {
	tests := []struct {
		name          string
		allowedNet    string
		allocated     []NetworkBlock
		reserved      []ReservedRange
		blockSize     int
		expected      string
		expectError   bool
		errorContains string
	}{
		{
			name:       "Empty allocations and reservations",
			allowedNet: "10.43.0.0/16",
			allocated:  []NetworkBlock{},
			reserved:   []ReservedRange{},
			blockSize:  24,
			expected:   "10.43.0.0",
		},
		{
			name:       "Skip reserved range at beginning",
			allowedNet: "10.43.0.0/16",
			allocated:  []NetworkBlock{},
			reserved: []ReservedRange{
				{CIDR: "10.43.0.0/24"},
			},
			blockSize: 24,
			expected:  "10.43.1.0",
		},
		{
			name:       "Skip multiple reserved ranges",
			allowedNet: "10.43.0.0/16",
			allocated:  []NetworkBlock{},
			reserved: []ReservedRange{
				{CIDR: "10.43.0.0/24"},
				{CIDR: "10.43.1.0/24"},
				{CIDR: "10.43.200.0/24"},
			},
			blockSize: 24,
			expected:  "10.43.2.0",
		},
		{
			name:       "Find gap between allocated ranges",
			allowedNet: "10.43.0.0/16",
			allocated: []NetworkBlock{
				{StartIP: "10.43.0.0", CIDR: "10.43.0.0/24", BlockSize: 24},
				{StartIP: "10.43.2.0", CIDR: "10.43.2.0/24", BlockSize: 24},
			},
			reserved:  []ReservedRange{},
			blockSize: 24,
			expected:  "10.43.1.0",
		},
		{
			name:          "IPv6 network (not supported)",
			allowedNet:    "2001:db8::/64",
			blockSize:     112,
			expectError:   true,
			errorContains: "IPv6 is not currently supported",
		},
		{
			name:          "Invalid block size",
			allowedNet:    "10.43.0.0/16",
			blockSize:     33,
			expectError:   true,
			errorContains: "invalid block size",
		},
		{
			name:       "No space left - all allocated",
			allowedNet: "10.43.0.0/24",
			allocated: []NetworkBlock{
				{StartIP: "10.43.0.0", CIDR: "10.43.0.0/24", BlockSize: 24},
			},
			blockSize:     24,
			expectError:   true,
			errorContains: "no available address after occupied range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowedPrefix, err := netip.ParsePrefix(tt.allowedNet)
			require.NoError(t, err)

			result, err := FindNextAvailableBlock(allowedPrefix, tt.allocated, tt.reserved, tt.blockSize)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result.String())
		})
	}
}

// Test for complex allocation scenarios
func TestComplexAllocationScenarios(t *testing.T) {
	t.Run("K8s CIDR with multiple reserved ranges", func(t *testing.T) {
		allowedPrefix, err := netip.ParsePrefix("10.43.0.0/16")
		require.NoError(t, err)

		reserved := []ReservedRange{
			{CIDR: "10.43.0.0/24", Description: "K8s system"},
			{CIDR: "10.43.200.0/24", Description: "ClusterIP services"},
			{CIDR: "10.43.255.0/24", Description: "Reserved"},
		}

		allocated := []NetworkBlock{
			{StartIP: "10.43.1.0", CIDR: "10.43.1.0/24", BlockSize: 24},
			{StartIP: "10.43.2.0", CIDR: "10.43.2.0/24", BlockSize: 24},
		}

		// Should find next available after allocated ranges
		result, err := FindNextAvailableBlock(allowedPrefix, allocated, reserved, 24)
		require.NoError(t, err)
		assert.True(t, result.IsValid())
		assert.Equal(t, "10.43.3.0", result.String())
	})
}

func TestIPHelperFunctions(t *testing.T) {
	t.Run("GetFirstUsableIP", func(t *testing.T) {
		prefix, err := netip.ParsePrefix("10.43.1.0/24")
		require.NoError(t, err)

		firstUsable := GetFirstUsableIP(prefix)
		assert.Equal(t, "10.43.1.1", firstUsable.String())
	})

	t.Run("GetLastUsableIP", func(t *testing.T) {
		prefix, err := netip.ParsePrefix("10.43.1.0/24")
		require.NoError(t, err)

		lastUsable := GetLastUsableIP(prefix)
		assert.Equal(t, "10.43.1.254", lastUsable.String())
	})

	t.Run("GetIPRangeInfo", func(t *testing.T) {
		info, err := GetIPRangeInfo("10.43.1.0/24")
		require.NoError(t, err)

		assert.Equal(t, "10.43.1.0", info.Network)
		assert.Equal(t, "10.43.1.1", info.Gateway)
		assert.Equal(t, "10.43.1.255", info.Broadcast)
		assert.Equal(t, "10.43.1.1", info.FirstUsable)
		assert.Equal(t, "10.43.1.254", info.LastUsable)
		assert.Equal(t, 256, info.TotalIPs)
		assert.Equal(t, 254, info.UsableIPs)
	})

	t.Run("IPToUint32 and Uint32ToIP", func(t *testing.T) {
		// Test conversion of IP to uint32 and back
		originalIP, err := netip.ParseAddr("192.168.1.10")
		require.NoError(t, err)

		// Convert to uint32
		intVal, err := IPToUint32(originalIP)
		require.NoError(t, err)
		assert.Equal(t, uint32(3232235786), intVal) // 192.168.1.10 as uint32

		// Convert back to IP
		resultIP := Uint32ToIP(intVal)
		assert.Equal(t, originalIP.String(), resultIP.String())
	})

	t.Run("IsSubnetNameOf", func(t *testing.T) {
		assert.True(t, IsSubnetNameOf("network1-subnet1", "network1"))
		assert.True(t, IsSubnetNameOf("network1-sequencers", "network1"))
		assert.False(t, IsSubnetNameOf("network1", "network1"))
		assert.False(t, IsSubnetNameOf("network2-subnet", "network1"))
		assert.False(t, IsSubnetNameOf("prefix-network1", "network1"))
	})
}

func TestSubnetCalculation(t *testing.T) {
	t.Run("calculate subnet within parent network", func(t *testing.T) {
		// Parent: 10.43.0.0/24
		parentAddr, err := netip.ParseAddr("10.43.0.0")
		require.NoError(t, err)

		// Calculate first /28 subnet (offset 0)
		parentAddrInt, err := IPToUint32(parentAddr)
		require.NoError(t, err)

		subnetSize := 1 << (32 - 28) // 2^(32-28) = 2^4 = 16 addresses

		firstSubnetAddr := Uint32ToIP(parentAddrInt)
		firstSubnet := netip.PrefixFrom(firstSubnetAddr, 28)
		assert.Equal(t, "10.43.0.0/28", firstSubnet.String())

		// Calculate second /28 subnet (offset 1)
		secondSubnetAddr := Uint32ToIP(parentAddrInt + uint32(subnetSize))
		secondSubnet := netip.PrefixFrom(secondSubnetAddr, 28)
		assert.Equal(t, "10.43.0.16/28", secondSubnet.String())

		// Calculate the 16th /28 subnet (offset 15)
		lastSubnetAddr := Uint32ToIP(parentAddrInt + uint32(15*subnetSize))
		lastSubnet := netip.PrefixFrom(lastSubnetAddr, 28)
		assert.Equal(t, "10.43.0.240/28", lastSubnet.String())
	})
}

func TestBlockSizeEscapesCIDR(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		blockSize int
		expected  bool
	}{
		{
			name:      "block size = prefix bits",
			prefix:    "10.43.0.0/24",
			blockSize: 24,
			expected:  false,
		},
		{
			name:      "block size < prefix bits",
			prefix:    "10.43.0.0/24",
			blockSize: 16,
			expected:  true,
		},
		{
			name:      "block size > than prefix bits",
			prefix:    "10.43.0.0/16",
			blockSize: 24,
			expected:  false,
		},
		{
			name:      "IPv6 prefix with matching block size",
			prefix:    "2001:db8::/64",
			blockSize: 64,
			expected:  false,
		},
		{
			name:      "IPv6 prefix with smaller block size",
			prefix:    "2001:db8::/64",
			blockSize: 48,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.prefix)
			require.NoError(t, err)

			result := blockSizeEscapesCIDR(tt.blockSize, prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func splitRange(t *testing.T, r string) []string {
	parts := []string{}
	for i := 0; i < len(r); i++ {
		if r[i] == '-' {
			parts = append(parts, r[:i], r[i+1:])
			break
		}
	}
	require.Len(t, parts, 2, "Range format should be 'start-end'")
	return parts
}
