package main

import (
	"log"
	"pr_agent/internal"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
)

var globalConfig atomic.Value // 存储*internal.Config

func watchConfigChanges(configPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("配置热重载监听失败: %v", err)
		return
	}
	defer watcher.Close()
	watcher.Add(configPath)
	for event := range watcher.Events {
		if event.Op&fsnotify.Write == fsnotify.Write {
			if cfg, err := internal.LoadConfig(configPath); err == nil {
				globalConfig.Store(cfg)
				log.Printf("配置已热重载")
			} else {
				log.Printf("配置热重载失败: %v", err)
			}
		}
	}
}

func main() {
	cfg, err := internal.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}
	globalConfig.Store(cfg)
	go watchConfigChanges("config.yaml")

	// 初始化SQLite存储
	storage := internal.NewStorage("pr_agent.db")

	r := gin.Default()
	// 中间件：每次请求都注入 config
	r.Use(func(c *gin.Context) {
		cfg := globalConfig.Load().(*internal.Config)
		c.Set("config", cfg)
		c.Next()
	})
	internal.RegisterResultRoute(r, storage) // 注册 /results 路由
	r.POST("/webhook", func(c *gin.Context) {
		cfg := globalConfig.Load().(*internal.Config)
		if !cfg.EnableWebhook {
			c.JSON(403, gin.H{"error": "Webhook 功能已关闭 (EnableWebhook=false)"})
			return
		}
		internal.WebhookHandler(cfg, storage)(c)
	})
	r.Static("/static", "./web")
	r.StaticFile("/", "./web/index.html")

	go internal.StartPollingWithDynamicConfig(&globalConfig, storage) // 启动主动轮询 goroutine

	log.Printf("服务启动于 %s", cfg.Listen)
	r.Run(cfg.Listen)
}
