package ipallocator

// ServiceName is the name of the IPAllocator service in Restate
const ServiceName = "AltDAIPAllocator"

// Method names for the IPAllocator service
const (
	MethodAllocateNetworkBlock      = "AllocateNetworkBlock"
	MethodAllocateSubnetBlock       = "AllocateSubnetBlock"
	MethodReleaseNetworkBlock       = "ReleaseNetworkBlock"
	MethodReleaseSubnetBlock        = "ReleaseSubnetBlock"
	MethodGetNetworkBlock           = "GetNetworkBlock"
	MethodGetAllocatedNetworkBlocks = "GetAllocatedNetworkBlocks"
	MethodHasNetworkBlock           = "HasNetworkBlock"
	MethodGetReservedRanges         = "GetReservedRanges"
	MethodInitialize                = "Initialize"
)
