package route

import (
	"io"

	"github.com/metacubex/mihomo/component/panelrt"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// MeowX：主控实时通道与入口覆盖表的控制接口（规格 miaomiaowuC/Design/entry-realtime.md §7），给内核以独立程序运行的外壳
// （OpenWrt 版、飞牛 NAS 版）用；安卓 / Windows / Linux 客户端经桥接直接调 component/panelrt 的同一套函数，不走这里。
//
//	PUT    /meowx/realtime   panelrt.Config：{"channels":[{"base","token"|"rt"}],"hook":{"exec":[…]}|{"url":"…"},"subs":[{"base","key","rev"}]}
//	                         或单个 {"base","token"|"rt","hook":…}；空正文 / 空列表 = 停掉。回当前状态；参数不对 400 + {"message"}
//	GET    /meowx/realtime   各通道状态（panelrt.StatusInfo）
//	DELETE /meowx/realtime   停掉全部通道（入口覆盖表留着）
//	GET    /meowx/entries    当前入口覆盖表 {"entries":[…]}（entryoverride.View；"ports" 没有 = 主控没给、只比 server，[] = 不匹配任何节点；
//	                         "names" = 入口服务器名称 IP → 名字，只有管理员账号的连接才有，一个都没有时不出这个字段）
//	DELETE /meowx/entries    清掉入口覆盖（?source=<主控地址> 只清那个主控的；退出登录、删掉那个主控的全部订阅时用）
func meowxRealtimeRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, panelrt.Status())
	})
	r.Put("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if err := panelrt.ApplyJSON(body); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.JSON(w, r, panelrt.Status())
	})
	r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
		panelrt.Stop()
		render.NoContent(w, r)
	})
	return r
}

func meowxEntriesRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, render.M{"entries": panelrt.Entries()})
	})
	r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
		n := panelrt.ClearEntries(r.URL.Query().Get("source"))
		render.JSON(w, r, render.M{"cleared": n})
	})
	return r
}
