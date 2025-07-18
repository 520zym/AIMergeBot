package internal

import (
	"fmt"
	"log"
	"time"

	"github.com/xanzy/go-gitlab"
	"encoding/json"
	"os"
)

const analyzedMRsFile = "analyzed_mrs.json"

func loadAnalyzedMRs() map[string]struct{} {
	m := make(map[string]struct{})
	f, err := os.Open(analyzedMRsFile)
	if err != nil {
		return m // 文件不存在则返回空map
	}
	defer f.Close()
	var arr []string
	if err := json.NewDecoder(f).Decode(&arr); err == nil {
		for _, k := range arr {
			m[k] = struct{}{}
		}
	}
	return m
}

func saveAnalyzedMRs(m map[string]struct{}) {
	arr := make([]string, 0, len(m))
	for k := range m {
		arr = append(arr, k)
	}
	f, err := os.Create(analyzedMRsFile)
	if err != nil {
		log.Printf("无法保存已分析MR记录: %v", err)
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(arr)
}

func GetMRDiff(git *gitlab.Client, projectID int, mrIID int) (string, error) {
	opts := &gitlab.GetMergeRequestChangesOptions{}
	mr, _, err := git.MergeRequests.GetMergeRequestChanges(projectID, mrIID, opts)
	if err != nil {
		return "", err
	}
	if mr == nil || mr.Changes == nil {
		return "", nil
	}
	diff := ""
	for _, change := range mr.Changes {
		diff += "File: " + change.NewPath + "\n"
		diff += change.Diff + "\n"
	}
	return diff, nil
}

func StartPolling(cfg *Config) {
	analyzed := loadAnalyzedMRs() // key: projectID-mrIID
	git, err := gitlab.NewClient(cfg.GitLab.Token, gitlab.WithBaseURL(cfg.GitLab.URL+"/api/v4"))
	if err != nil {
		log.Printf("GitLab 客户端初始化失败: %v", err)
		return
	}
	for {
		for _, p := range cfg.Projects {
			mrs, _, err := git.MergeRequests.ListProjectMergeRequests(p.ID, &gitlab.ListProjectMergeRequestsOptions{
				State: gitlab.String("opened"),
			})
			if err != nil {
				log.Printf("获取项目 %v MR 失败: %v", p.Name, err)
				continue
			}
			for _, mr := range mrs {
				key := fmt.Sprintf("%d-%d", p.ID, mr.IID)
				if _, ok := analyzed[key]; ok {
					continue
				}
				diff, err := GetMRDiff(git, p.ID, mr.IID)
				if err != nil {
					log.Printf("获取 MR diff 失败: %v", err)
					continue
				}
				log.Printf("分析 MR !%d diff 内容:\n%s", mr.IID, diff)
				// 拉取 MR 详情
				mrDetail, _, err := git.MergeRequests.GetMergeRequest(p.ID, mr.IID, nil)
				if err != nil {
					log.Printf("获取 MR 详情失败: %v", err)
					continue
				}
				project, _, err := git.Projects.GetProject(p.ID, nil)
				if err != nil {
					log.Printf("获取项目详情失败: %v", err)
					continue
				}
				issues, err := AnalyzeDiffWithOpenAI(cfg.OpenAI.APIKey, diff, cfg.OpenAI.URL, cfg.OpenAI.Model)
				if err != nil {
					log.Printf("AI 分析失败: %v", err)
					continue
				}
				analyzed[key] = struct{}{}
				saveAnalyzedMRs(analyzed)
				ResultsMu.Lock()
				Results = append(Results, MRAnalysisResult{
					MRID:          mr.IID,
					ProjectID:     p.ID,
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
				log.Printf("分析完成: 项目 %v MR !%d", p.Name, mr.IID)
				log.Printf("AI 分析结构化结果: %+v", issues)
			}
		}
		time.Sleep(5 * time.Second)
	}
}
