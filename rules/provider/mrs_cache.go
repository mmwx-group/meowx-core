package provider

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

// 规则集编译缓存（MeowX 加的）：text / yaml 格式的 domain / ipcidr 规则集，第一次照常解析，
// 顺手把结果按 mrs 格式写到规则集文件旁边的 `<文件>.meow.mrs`，开头 32 字节是
// sha256(格式 ‖ 原文)；之后原文没变就直接读这份 mrs，不再逐行解析（大列表解析时的
// 临时内存与 CPU 都省掉：20 万条域名，text 分配 80MB、yaml 分配约 1.4GB，mrs 只有 18MB）。
// 读失败、哈希不符一律退回正常解析并重写缓存；写失败只记日志。
// 只给 http 规则集用：缓存放在内核自己的 providers 目录里，不往用户的本地文件旁边写。

const mrsCacheSuffix = ".meow.mrs"

func mrsCachePath(vehicle P.Vehicle) string {
	if vehicle == nil || vehicle.Type() != P.HTTP || vehicle.Path() == "" {
		return ""
	}
	return vehicle.Path() + mrsCacheSuffix
}

func mrsCacheKey(buf []byte, format P.RuleFormat) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(format.String()))
	h.Write([]byte{0})
	h.Write(buf)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

func cachedRulesParse(cachePath string, buf []byte, strategy ruleStrategy, format P.RuleFormat) (ruleStrategy, error) {
	if cachePath == "" || format == P.MrsRule {
		return rulesParse(buf, strategy, format)
	}
	if _, ok := strategy.(mrsRuleStrategy); !ok { // classical 没有 mrs 形式
		return rulesParse(buf, strategy, format)
	}

	key := mrsCacheKey(buf, format)
	if cached, err := os.ReadFile(cachePath); err == nil && len(cached) > len(key) && bytes.Equal(cached[:len(key)], key[:]) {
		if s, err := rulesParse(cached[len(key):], strategy, P.MrsRule); err == nil {
			return s, nil
		} else {
			log.Warnln("[RuleProvider] read mrs cache %s failed, reparse: %s", cachePath, err)
		}
	}

	s, err := rulesParse(buf, strategy, format)
	if err != nil {
		return nil, err
	}
	if s.Count() > 0 {
		if err := writeMrsCache(cachePath, key, s.(mrsRuleStrategy)); err != nil {
			log.Warnln("[RuleProvider] write mrs cache %s failed: %s", cachePath, err)
		}
	}
	return s, nil
}

// writeMrsCache 先写临时文件再改名，别让半份缓存被下次启动读到（哈希对得上但内容截断）。
func writeMrsCache(cachePath string, key [sha256.Size]byte, strategy mrsRuleStrategy) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(cachePath), filepath.Base(cachePath)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 改名成功后它已不存在
	if _, err = tmp.Write(key[:]); err == nil {
		err = writeMrs(tmp, strategy, strategy.Behavior())
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, cachePath)
}
