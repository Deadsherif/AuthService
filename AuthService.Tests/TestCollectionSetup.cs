using Xunit;

// AuthValidateTests and OnlineTimeAnchorTests both mutate the shared static seams on
// AuthService.Auth (GateFactory, NowProvider, OnlineTimeProvider, DeviceProvider). xUnit
// runs distinct test classes in parallel by default, which races on those statics and
// produces flaky results. Disable cross-test parallelization for this assembly so tests
// that share process-global mutable state cannot interleave.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
