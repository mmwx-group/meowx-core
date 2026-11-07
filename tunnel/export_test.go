package tunnel

// 给外部测试包用（tunnel_test 要引 adapter 造出站，内部测试包引它会成环）
var ResolveMetadataForTest = resolveMetadata
