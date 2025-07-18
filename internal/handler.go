package internal

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/xanzy/go-gitlab"
)

var (
	ResultsMu sync.Mutex
	Results   []MRAnalysisResult
)

func RegisterResultRoute(r *gin.Engine) {
	r.GET("/results", GetResultsHandler)
}

func GetResultsHandler(c *gin.Context) {
	ResultsMu.Lock()
	defer ResultsMu.Unlock()
	c.JSON(200, gin.H{"results": Results})
}

func WebhookHandler(cfg *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "读取请求体失败"})
			return
		}
		var event struct {
			ObjectKind string `json:"object_kind"`
			Project    struct {
				ID int `json:"id"`
			} `json:"project"`
			ObjectAttributes struct {
				IID   int    `json:"iid"`
				State string `json:"state"`
			} `json:"object_attributes"`
		}
		if err := json.Unmarshal(body, &event); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "解析事件失败"})
			return
		}
		if event.ObjectKind != "merge_request" || event.ObjectAttributes.State != "opened" {
			c.JSON(http.StatusOK, gin.H{"msg": "非 MR 打开事件，忽略"})
			return
		}
		git, err := gitlab.NewClient(cfg.GitLab.Token, gitlab.WithBaseURL(cfg.GitLab.URL+"/api/v4"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "GitLab 客户端初始化失败"})
			return
		}
		// 拉取 MR 详情
		mrDetail, _, err := git.MergeRequests.GetMergeRequest(event.Project.ID, event.ObjectAttributes.IID, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取 MR 详情失败"})
			return
		}
		project, _, err := git.Projects.GetProject(event.Project.ID, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取项目详情失败"})
			return
		}
		diff, err := GetMRDiff(git, event.Project.ID, event.ObjectAttributes.IID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取 MR diff 失败"})
			return
		}
		log.Printf("Webhook 分析 MR !%d diff 内容:\n%s", event.ObjectAttributes.IID, diff)
		issues, err := AnalyzeDiffWithOpenAI(cfg.OpenAI.APIKey, diff, cfg.OpenAI.URL, cfg.OpenAI.Model)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "AI 分析失败"})
			return
		}
		log.Printf("AI 分析结构化结果: %+v", issues)
		ResultsMu.Lock()
		Results = append(Results, MRAnalysisResult{
			MRID:          event.ObjectAttributes.IID,
			ProjectID:     event.Project.ID,
			ProjectName:   project.Name,
			ProjectPath:   project.PathWithNamespace,
			MRTitle:       mrDetail.Title,
			MRAuthor:      mrDetail.Author.Username,
			MRCreated:     mrDetail.CreatedAt.String(),
			MRBranch:      mrDetail.SourceBranch,
			MRDesc:        mrDetail.Description,
			MRUrl:         mrDetail.WebURL,
			GitLabBaseUrl: cfg.GitLab.URL,
			Result:        issues,
		})
		ResultsMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"msg": "分析完成"})
	}
}
