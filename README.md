# AIMergeBot

> 🚀 自动化代码安全审查平台，支持 GitLab MR ，AI 智能检测 SQL注入、XSS、敏感信息泄露等风险，开箱即用！

---

## 功能亮点
- **支持 GitLab Merge Request（MR）自动安全审查**
- **AI 智能检测**：SQL注入、XSS、CSRF、敏感信息泄露、SSRF、依赖风险等
- **结构化结果**：风险类型、等级、建议、上下文一目了然
- **主动/被动双模式**：支持定时轮询和 Webhook
- - **本地持久化**：已分析过的MR会记录在本地文件，系统重启不会重复分析
- **多项目支持**，配置灵活
- **一键部署，开箱即用**

---

## 快速开始

### 1. 克隆项目
```bash
git clone https://github.com/Ed1s0nZ/AIMergeBot.git
cd AIMergeBot
```

### 2. 安装依赖
```bash
go mod tidy
```

### 3. 配置 `config.yaml`
```yaml
listen: ":8080"
gitlab:
  token: "<your-gitlab-token>"
  url: "https://gitlab.com"
openai:
  api_key: "<your-openai-key>"
  url: "https://api.openai.com/v1"
  model: "gpt-3.5-turbo"
projects:
  - id: 123456
    name: "your-group/your-project"
enable_polling: true
enable_webhook: true
```
- `id` 为项目数字ID（见 GitLab 项目设置）
- `enable_polling` 主动轮询，`enable_webhook` 支持 Webhook

### 4. 运行服务
```bash
go run main.go
```

### 5. 配置 GitLab Webhook（可选）
- 在项目设置 Webhook，URL 填 `http://你的服务器:8080/webhook`
- 事件选择 Merge Request

### 6. 访问前端
浏览器打开 [http://localhost:8080/](http://localhost:8080/) 查看安全分析结果

---

## 界面预览
1. 展示界面：   
  ![界面预览](./image/展示.png)

2. 详情界面：      
  ![详情预览](./image/详情.png)

3. 评论界面：   
  ![详情预览](./image/评论.png)

---

## 常见问题 FAQ

**Q: 支持 GitHub PR 吗？**   
**A: 当前仅支持 GitLab MR，GitHub PR 暂不支持。**   

**Q: 支持哪些 AI 大模型？**   
A: 支持 OpenAI 兼容 API（gpt-3.5-turbo/gpt-4/moonshot/qwen/glm等），可自定义模型和API地址。   

**Q: 如何获取项目ID？**   
A: 见 GitLab 项目设置页面底部，或用 API 查询。   

**Q: 支持多项目吗？**   
A: 支持，`projects` 列表可配置多个项目。   

**Q: 支持自建/私有 GitLab 吗？**   
A: 支持，`gitlab.url` 填你的私有地址即可。   

**Q: 如何自定义分析频率？**   
A: 修改 `internal/gitlab.go` 里的 `time.Sleep` 参数。   

