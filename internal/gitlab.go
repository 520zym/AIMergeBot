package internal

import (
	"fmt"
	"log"
	"time"

	"sync/atomic"

	"github.com/xanzy/go-gitlab"
)

// 移除analyzedMRsFile、loadAnalyzedMRs、saveAnalyzedMRs等

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

func formatMRComment(issues []SecurityIssue) string {
	if len(issues) == 0 {
		return "🔍 **AI安全审查完成**\n\n✅ 未发现明显安全问题，代码经AI初步分析未发现高风险项。"
	}

	comment := "🔍 **AIMergeBot 安全审查完成**\n\n"
	comment += "⚠️ **初步分析发现以下可能存在的安全风险（结果由 AI 提供，仅供参考）：**\n\n"

	for i, issue := range issues {
		levelEmoji := "🔴"
		if issue.Level == "medium" {
			levelEmoji = "🟡"
		} else if issue.Level == "low" {
			levelEmoji = "🟢"
		}

		comment += fmt.Sprintf("### %d. %s %s (%s)\n\n", i+1, levelEmoji, issue.Type, issue.Level)
		comment += fmt.Sprintf("**描述：** %s\n\n", issue.Desc)
		if issue.File != "" {
			comment += fmt.Sprintf("**文件：** %s\n\n", issue.File)
		}
		if issue.Code != "" {
			comment += fmt.Sprintf("**问题代码：**\n```\n%s\n```\n", issue.Code)
		}
		comment += fmt.Sprintf("**建议：** %s\n\n", issue.Suggestion)
		if issue.Context != "" {
			comment += fmt.Sprintf("**上下文：** %s\n\n", issue.Context)
		}

		// 添加修复建议
		if issue.FixSuggestion != "" {
			comment += fmt.Sprintf("**🔧 智能修复建议：**\n\n%s\n\n", issue.FixSuggestion)
		}

		comment += "\n---\n\n"
	}

	comment += "💡 **请结合实际业务场景和人工审核，判断上述问题是否真实存在。AI分析结果仅供参考，不能保证绝对准确。**\n\n"
	comment += "🤖 *本评论由AI自动生成，修复建议仅供参考，请根据实际情况进行调整。*"
	return comment
}

func addMRComment(git *gitlab.Client, projectID, mrIID int, comment string) error {
	_, _, err := git.Discussions.CreateMergeRequestDiscussion(projectID, mrIID, &gitlab.CreateMergeRequestDiscussionOptions{
		Body: gitlab.String(comment),
	})
	return err
}

func StartPollingWithDynamicConfig(globalConfig *atomic.Value, storage *Storage) {
	var lastToken, lastURL string
	var git *gitlab.Client
	initialized := false
	for {
		cfg := globalConfig.Load().(*Config)
		if !cfg.EnablePolling {
			log.Println("[AIMergeBot] EnablePolling=false，跳过本轮定时轮询，10秒后重试……")
			time.Sleep(10 * time.Second)
			continue
		}
		log.Printf("[AIMergeBot] 进入定时轮询扫描循环 | 时间: %s | 配置项目数: %d | 项目: [%s] | ScanExistingMRs: %v | EnableWebhook: %v", time.Now().Format("2006-01-02 15:04:05"), len(cfg.Projects), func() string {
			var s string
			for i, p := range cfg.Projects {
				if i > 0 {
					s += ", "
				}
				s += fmt.Sprintf("%d:%s", p.ID, p.Name)
			}
			return s
		}(), cfg.ScanExistingMRs, cfg.EnableWebhook)
		if git == nil || cfg.GitLab.Token != lastToken || cfg.GitLab.URL != lastURL {
			var err error
			git, err = gitlab.NewClient(cfg.GitLab.Token, gitlab.WithBaseURL(cfg.GitLab.URL+"/api/v4"))
			if err != nil {
				log.Printf("GitLab 客户端初始化失败: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			lastToken = cfg.GitLab.Token
			lastURL = cfg.GitLab.URL
			initialized = false
		}
		// 只在首次初始化时处理存量MR
		if !initialized && !cfg.ScanExistingMRs {
			for _, p := range cfg.Projects {
				mrs, _, err := git.MergeRequests.ListProjectMergeRequests(p.ID, &gitlab.ListProjectMergeRequestsOptions{
					State: gitlab.String("opened"),
				})
				if err != nil {
					log.Printf("获取项目 %v MR 失败: %v", p.Name, err)
					continue
				}
				for _, mr := range mrs {
					storage.SetAnalyzedStatus(p.ID, mr.IID, "done")
				}
			}
			initialized = true
		}
		for _, p := range cfg.Projects {
			mrs, _, err := git.MergeRequests.ListProjectMergeRequests(p.ID, &gitlab.ListProjectMergeRequestsOptions{
				State: gitlab.String("opened"),
			})
			if err != nil {
				log.Printf("获取项目 %v MR 失败: %v", p.Name, err)
				continue
			}
			for _, mr := range mrs {
				status, _ := storage.GetAnalyzedStatus(p.ID, mr.IID)
				if status == "processing" || status == "done" {
					continue
				}
				storage.SetAnalyzedStatus(p.ID, mr.IID, "processing")
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

				// 为每个安全问题生成修复建议
				for i := range issues {
					if fixSuggestion, err := generateFixSuggestion(cfg.OpenAI.APIKey, cfg.OpenAI.URL, cfg.OpenAI.Model, issues[i]); err == nil {
						issues[i].FixSuggestion = fixSuggestion
						log.Printf("已为问题 %d 生成修复建议", i+1)
					} else {
						log.Printf("生成修复建议失败: %v", err)
						issues[i].FixSuggestion = "修复建议生成失败，请手动处理"
					}
				}

				// 标记为已分析，避免重复
				storage.SetAnalyzedStatus(p.ID, mr.IID, "done")
				storage.AddResult(MRAnalysisResult{
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

				// 如果启用了MR评论功能，则对MR进行评论
				if cfg.EnableMRComment {
					comment := formatMRComment(issues)
					if err := addMRComment(git, p.ID, mr.IID, comment); err != nil {
						log.Printf("添加MR评论失败: %v", err)
					} else {
						log.Printf("已为MR !%d添加安全审查评论", mr.IID)
					}
				}

				log.Printf("分析完成: 项目 %v MR !%d", p.Name, mr.IID)
				log.Printf("AI 分析结构化结果: %+v", issues)
			}
		}
		time.Sleep(5 * time.Second)
	}
}
