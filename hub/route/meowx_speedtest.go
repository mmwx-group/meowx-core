package route

import (
	"github.com/metacubex/mihomo/component/speedtest"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// MeowX：网络测速的控制接口，给内核以独立程序运行的外壳（OpenWrt 版、飞牛 NAS 版）的网页用；
// 安卓 / Windows / Linux 客户端经桥接直接调同一个 component/speedtest，不走这里。
//
//	GET  /meowx/speedtest        当前进度（speedtest.Progress，idle = 还没测过）
//	POST /meowx/speedtest/start  {"source","proxy","connections"} 开始（已有一次在跑就先取消）；没能开始时 400 + {"message"}
//	POST /meowx/speedtest/stop   取消
//	POST /meowx/speedtest/board  speedtest.BoardRequest：经测速用的同一个出站发一次测速榜请求，回 BoardResponse（至多阻塞 10 秒）
func meowxSpeedTestRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, speedtest.Status())
	})
	r.Post("/start", func(w http.ResponseWriter, r *http.Request) {
		var params speedtest.Params
		if err := render.DecodeJSON(r.Body, &params); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if msg := speedtest.Start(params); msg != "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(msg))
			return
		}
		render.NoContent(w, r)
	})
	r.Post("/stop", func(w http.ResponseWriter, r *http.Request) {
		speedtest.Stop()
		render.NoContent(w, r)
	})
	r.Post("/board", func(w http.ResponseWriter, r *http.Request) {
		var req speedtest.BoardRequest
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		render.JSON(w, r, speedtest.BoardSend(req))
	})
	return r
}
