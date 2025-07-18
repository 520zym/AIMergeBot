package main

import (
	"log"
	"pr_agent/internal"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := internal.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}

	r := gin.Default()
	internal.RegisterResultRoute(r) // 只注册 /results
	r.POST("/webhook", internal.WebhookHandler(cfg))
	r.Static("/static", "./web")
	r.StaticFile("/", "./web/index.html")

	go internal.StartPolling(cfg) // 启动主动轮询 goroutine

	log.Printf("服务启动于 %s", cfg.Listen)
	r.Run(cfg.Listen)
}
