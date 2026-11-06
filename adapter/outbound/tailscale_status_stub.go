//go:build !with_gvisor || no_tailscale

package outbound

import "context"

// TailscaleStatusByName 不带 tailscale 的构建里没有这种出站。
func TailscaleStatusByName(ctx context.Context, name string) (*TailscaleStatus, error) {
	return nil, nil
}
