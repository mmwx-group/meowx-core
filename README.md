# MeowX Core

MeowX 各端共用的代理内核：[mihomo](https://github.com/MetaCubeX/mihomo) 的 fork（以 Bettbox v1.19.2 为基线导入，
已同步到上游 v1.19.33），比官方多 Miu、AnyTLS + REALITY、Snell v6、测速 / 测速榜等。

原先放在 [meowC](https://github.com/mmwx-group/meowC) 的 `core/Clash.Meta`，这里是拆出来的独立仓库（历史一并保留）。

## 谁在用

| 使用方 | 怎么引用 | 怎么跑 |
| --- | --- | --- |
| [meowC](https://github.com/mmwx-group/meowC)（Android / Windows） | git 子模块，挂在 `core/Clash.Meta`；`core/go.mod` 用 `replace` 指到这个目录 | 库模式：由 meowC 的 `core` 模块编成 libclash / MeowXCore，监听端口与 TUN 由客户端外壳起 |
| [meowx-openwrt](https://github.com/mmwx-group/meowx-openwrt)（`meowx-core` 包） | 按 tag 拉源码 | 独立程序：`main` 打开 `executor.StandaloneInbound`，自己起监听端口与 TUN；另有 `meowx-core panel …` 子命令 |

模块路径保持 `github.com/metacubex/mihomo` 不变（fork 的通常做法，方便同步上游、各端的 import 不用改）。

### 补丁版 sing-tun

`third_party/sing-tun` 是打过补丁的 sing-tun（TCP accept 循环遇到暂时性错误不再永久退出，见其 README），
本仓库的 `go.mod` 用 `replace` 指向它。Go 只认主模块里的 `replace`：把本仓库当依赖的一方（meowC）要在自己的
`go.mod` 里同样写一条，指向 `<子模块目录>/third_party/sing-tun`。

## 版本

tag 形如 `vX.Y.Z`，与各端的应用版本无关。发一个新内核：

1. 在这里提交、打 tag 并推送；
2. meowx-openwrt：把 `meowx-core/Makefile` 的 `PKG_VERSION` / `PKG_SOURCE_VERSION` 改到这个 tag，打 `core-vX.Y.Z` 发版——
   只更新内核，路由器上「关于」页的「更新内核」即可升级，不动插件本身；
3. meowC：在 `core/Clash.Meta` 子模块里切到这个 tag，提交子模块指针。

## 编译与测试

```sh
# 独立程序（OpenWrt 用的 tag）
go build -trimpath -tags with_gvisor,no_easytier,no_tailscale,no_zerotier -o meowx-core .

go test $(go list ./... | grep -v '^github.com/metacubex/mihomo$')
# main 包：main.go 在 init 里就 flag.Parse()（上游写法），会拒掉 go test 传入的 -test.* 参数，
# 所以编成测试二进制、不带参数跑
go test -c -o main.test . && ./main.test
```

## 许可

GPL-3.0，见 [LICENSE](LICENSE)。
