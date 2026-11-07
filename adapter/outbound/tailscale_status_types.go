package outbound

// MeowX：tailscale 出站给客户端界面看的状态（喵窝 / 组网节点的「已连接」、各设备直连还是中继）。
// 类型不带编译标签：桥层在不带 tailscale 的构建里也能引用（那时 TailscaleStatusByName 只回「没有这个出站」）。

// TailscaleStatus 本机状态与各对端。
type TailscaleStatus struct {
	// State 本机状态：NotStarted（还没启动）/ NoState / NeedsLogin / NeedsMachineAuth / Stopped / Starting / Running
	State string `json:"state"`
	// AuthURL 需要在浏览器里登录时的链接
	AuthURL string `json:"authURL,omitempty"`
	// Self 本机（登记过才有）
	Self *TailscalePeerStatus `json:"self,omitempty"`
	// Peers 对端（同一个 tailnet 里看得到的设备）
	Peers []TailscalePeerStatus `json:"peers"`
	// Health 健康检查的提示（连不上控制服务器、中继等）
	Health []string `json:"health,omitempty"`
	// MagicDNSSuffix MagicDNS 后缀
	MagicDNSSuffix string `json:"magicDNSSuffix,omitempty"`
}

// TailscalePeerStatus 一台设备。
type TailscalePeerStatus struct {
	// ID 控制服务器上的稳定编号（Headscale 就是数字编号，与主控设备列表的 id 相同）
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	DNSName   string   `json:"dnsName,omitempty"`
	OS        string   `json:"os,omitempty"`
	Addresses []string `json:"addresses"`
	// Online 连着控制服务器
	Online bool `json:"online"`
	// Active 最近有流量
	Active bool `json:"active"`
	// CurAddr 直连用的地址（空 = 没打通直连）
	CurAddr string `json:"curAddr,omitempty"`
	// Relay 用的中继区域
	Relay string `json:"relay,omitempty"`
	// LastSeen 离线时最后在线的时刻（RFC 3339）
	LastSeen string `json:"lastSeen,omitempty"`
}
