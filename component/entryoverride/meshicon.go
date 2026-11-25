package entryoverride

// 喵窝小标（同节点小标，只在 OpenWrt 打开 entryIcon 时给 zashboard 用）：喵窝白名单直连的节点（主控下发的 `_mmwx-mesh` 节点）
// 在 OpenWrt / NAS 版上走内核网卡 tailscale0，外壳生成运行配置时给它们写 `interface-name: tailscale0`
// （规格 miaomiaowuC/Design/meshnet-whitelist-direct.md §B3 / §B4）。控制接口的节点对象里 interface 是 tailscale0 的就带这个小标，
// 写法与入口小标相同（data:image/svg+xml,<svg>…，<title> 是悬停提示，不写 fill、跟着面板的文字色）。

// MeshInterface 喵窝在 OpenWrt / NAS 版上的内核网卡名（官方 tailscaled 的缺省名，两个外壳都用它）
const MeshInterface = "tailscale0"

// meshIconPath 三个设备节点连成三角（组网）：三个实心圆点 + 三条连线
const meshIconPath = `<path d="M12 2.5A2.5 2.5 0 1 1 12 7.5 2.5 2.5 0 0 1 12 2.5ZM4.5 16A2.5 2.5 0 1 1 4.5 21 2.5 2.5 0 0 1 4.5 16Z` +
	`M19.5 16A2.5 2.5 0 1 1 19.5 21 2.5 2.5 0 0 1 19.5 16ZM10.9 7.1 12.6 8.1 6.4 17.4 4.7 16.4Z` +
	`M13.1 7.1 19.3 16.4 17.6 17.4 11.4 8.1ZM6.5 17.6 17.5 17.6 17.5 19.4 6.5 19.4Z"/>`

// MeshIcon 节点经喵窝连接（出站网卡是 tailscale0）时的小标；节点小标没开或不是喵窝网卡回空
func MeshIcon(iface string) string {
	if !proxyIcon.Load() || iface != MeshInterface {
		return ""
	}
	return "data:image/svg+xml," +
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16"><title>` +
		xmlEscape("喵窝：经喵窝连接，不占服务器的 IP 白名单名额") + `</title>` + meshIconPath + `</svg>`
}
