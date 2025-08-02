package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/xanzy/go-gitlab"
)

// max 返回两个整数中的较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GitLabMCPTool 定义基于GitLab API的MCP工具结构
type GitLabMCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// GitLabMCPCall 定义GitLab MCP调用结构
type GitLabMCPCall struct {
	ToolName  string                 `json:"tool_name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// GitLabMCPResult 定义GitLab MCP调用结果
type GitLabMCPResult struct {
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`
}

// GitLabMCPTools 定义基于GitLab API的MCP工具
var GitLabMCPTools = []GitLabMCPTool{
	{
		Name:        "gitlab_search_code",
		Description: "在GitLab仓库中搜索指定的文本或模式",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "要搜索的文本或模式",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（如go、py、js）",
				},
			},
			"required": []string{"query"},
		},
	},
	{
		Name:        "gitlab_file_content",
		Description: "获取GitLab仓库中指定文件的内容",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "文件路径（相对于仓库根目录）",
				},
				"ref": map[string]interface{}{
					"type":        "string",
					"description": "分支或提交引用（可选，默认为默认分支）",
				},
			},
			"required": []string{"file_path"},
		},
	},
	{
		Name:        "gitlab_project_files",
		Description: "列出GitLab仓库中的文件和目录",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "目录路径（可选，默认为根目录）",
				},
				"ref": map[string]interface{}{
					"type":        "string",
					"description": "分支或提交引用（可选，默认为默认分支）",
				},
			},
		},
	},
	{
		Name:        "gitlab_commit_history",
		Description: "获取GitLab仓库的提交历史",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"since": map[string]interface{}{
					"type":        "string",
					"description": "开始时间（如：2024-01-01）",
				},
				"until": map[string]interface{}{
					"type":        "string",
					"description": "结束时间（如：2024-12-31）",
				},
				"author": map[string]interface{}{
					"type":        "string",
					"description": "作者过滤",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "特定文件路径",
				},
			},
		},
	},
	{
		Name:        "gitlab_mr_changes",
		Description: "获取Merge Request的详细变更信息",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"mr_iid": map[string]interface{}{
					"type":        "integer",
					"description": "Merge Request的IID",
				},
			},
			"required": []string{"mr_iid"},
		},
	},
}

// GitLabMCPExecutor 执行基于GitLab API的MCP工具调用
func GitLabMCPExecutor(call GitLabMCPCall, git *gitlab.Client, projectID int) GitLabMCPResult {
	// 记录工具调用开始
	log.Printf("GitLab MCP工具调用开始 - 工具名: %s", call.ToolName)
	
	if git == nil {
		log.Printf("GitLab MCP工具调用失败 - GitLab客户端为空")
		return GitLabMCPResult{
			Error: "GitLab客户端未初始化",
		}
	}
	
	var result GitLabMCPResult
	switch call.ToolName {
	case "gitlab_search_code":
		log.Printf("执行gitlab_search_code工具")
		result = executeGitLabSearchCode(call.Arguments, git, projectID)
	case "gitlab_file_content":
		log.Printf("执行gitlab_file_content工具")
		result = executeGitLabFileContent(call.Arguments, git, projectID)
	case "gitlab_project_files":
		log.Printf("执行gitlab_project_files工具")
		result = executeGitLabProjectFiles(call.Arguments, git, projectID)
	case "gitlab_commit_history":
		log.Printf("执行gitlab_commit_history工具")
		result = executeGitLabCommitHistory(call.Arguments, git, projectID)
	case "gitlab_mr_changes":
		log.Printf("执行gitlab_mr_changes工具")
		result = executeGitLabMRChanges(call.Arguments, git, projectID)
	default:
		log.Printf("GitLab MCP工具调用失败 - 未知工具: %s", call.ToolName)
		result = GitLabMCPResult{
			Error: fmt.Sprintf("未知的工具: %s", call.ToolName),
		}
	}
	
	// 记录工具调用结果
	if result.Error != "" {
		log.Printf("GitLab MCP工具调用失败 - 工具名: %s, 错误: %s", call.ToolName, result.Error)
	} else {
		log.Printf("GitLab MCP工具调用成功 - 工具名: %s, 输出长度: %d", call.ToolName, len(result.Content))
	}
	
	return result
}

// executeGitLabSearchCode 执行GitLab代码搜索
func executeGitLabSearchCode(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	query, ok := args["query"].(string)
	if !ok {
		log.Printf("gitlab_search_code工具执行失败 - query参数缺失或类型错误")
		return GitLabMCPResult{Error: "query参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)
	
	log.Printf("gitlab_search_code工具执行 - 查询: %s, 文件类型: %s", query, fileType)

	// 首先获取项目信息，确定默认分支
	project, _, err := git.Projects.GetProject(projectID, nil)
	if err != nil {
		log.Printf("gitlab_search_code工具执行失败 - 获取项目信息失败: %v", err)
		return GitLabMCPResult{Error: fmt.Sprintf("获取项目信息失败: %v", err)}
	}

	defaultBranch := project.DefaultBranch
	log.Printf("gitlab_search_code工具执行 - 使用默认分支: %s", defaultBranch)

	// 获取项目文件列表
	tree, _, err := git.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
		Recursive: gitlab.Bool(true),
		Ref:       &defaultBranch,
	})
	if err != nil {
		log.Printf("gitlab_search_code工具执行失败 - 获取文件列表失败: %v", err)
		return GitLabMCPResult{Error: fmt.Sprintf("获取文件列表失败: %v", err)}
	}

	log.Printf("gitlab_search_code工具执行 - 找到 %d 个文件", len(tree))

	// 搜索匹配的文件
	var searchResults []map[string]interface{}
	var processedFiles int
	var codeFiles int
	var readableFiles int
	
	for _, item := range tree {
		// 跳过目录
		if item.Type == "tree" {
			continue
		}
		
		processedFiles++
		log.Printf("gitlab_search_code工具执行 - 处理文件: %s", item.Path)

		// 检查文件类型过滤
		if fileType != "" && !strings.HasSuffix(item.Path, "."+fileType) {
			log.Printf("gitlab_search_code工具执行 - 跳过非目标类型文件: %s", item.Path)
			continue
		}

		// 只搜索代码文件
		codeExtensions := []string{".go", ".py", ".js", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".rs", ".swift", ".kt", ".scala"}
		isCodeFile := false
		for _, ext := range codeExtensions {
			if strings.HasSuffix(item.Path, ext) {
				isCodeFile = true
				break
			}
		}
		if !isCodeFile {
			log.Printf("gitlab_search_code工具执行 - 跳过非代码文件: %s", item.Path)
			continue
		}
		
		codeFiles++
		log.Printf("gitlab_search_code工具执行 - 搜索代码文件: %s", item.Path)
		
		// 获取文件内容进行搜索
		file, _, err := git.RepositoryFiles.GetFile(projectID, item.Path, &gitlab.GetFileOptions{
			Ref: &defaultBranch,
		})
		if err != nil {
			log.Printf("gitlab_search_code工具执行 - 跳过无法读取的文件: %s, 错误: %v", item.Path, err)
			continue
		}
		
		// 检查文件编码并解码
		var content string
		if file.Encoding == "base64" {
			// 解码Base64内容
			decodedBytes, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				log.Printf("gitlab_search_code工具执行 - 跳过Base64解码失败的文件: %s, 错误: %v", item.Path, err)
				continue
			}
			content = string(decodedBytes)
		} else {
			content = file.Content
		}
		
		readableFiles++
		log.Printf("gitlab_search_code工具执行 - 成功读取文件: %s, 大小: %d 字节, 编码: %s", item.Path, len(content), file.Encoding)
		
		// 在文件内容中搜索（不区分大小写）
		contentLower := strings.ToLower(content)
		queryLower := strings.ToLower(query)
		
		// 尝试多种搜索模式
		searchPatterns := []string{
			queryLower,
			strings.ReplaceAll(queryLower, ".", ""), // 移除点号
			strings.ReplaceAll(queryLower, ".", " "), // 点号替换为空格
		}
		
		found := false
		for _, pattern := range searchPatterns {
			if strings.Contains(contentLower, pattern) {
				log.Printf("gitlab_search_code工具执行 - 在文件 %s 中找到匹配: %s", item.Path, pattern)
				found = true
				break
			}
		}
		
		if found {
			// 找到匹配，提取上下文
			lines := strings.Split(content, "\n")
			var contextLines []string
			for i, line := range lines {
				lineLower := strings.ToLower(line)
				for _, pattern := range searchPatterns {
					if strings.Contains(lineLower, pattern) {
						// 添加上下文行
						start := max(0, i-2)
						end := min(len(lines), i+3)
						for j := start; j < end; j++ {
							contextLines = append(contextLines, fmt.Sprintf("%d: %s", j+1, lines[j]))
						}
						break
					}
				}
				if len(contextLines) > 0 {
					break
				}
			}
			
			searchResults = append(searchResults, map[string]interface{}{
				"filename": item.Path,
				"ref":      defaultBranch,
				"content":  strings.Join(contextLines, "\n"),
				"full_content": content,
			})
		} else {
			log.Printf("gitlab_search_code工具执行 - 在文件 %s 中未找到匹配", item.Path)
		}
	}
	
	log.Printf("gitlab_search_code工具执行 - 统计: 处理文件=%d, 代码文件=%d, 可读文件=%d", processedFiles, codeFiles, readableFiles)

	resultJSON, _ := json.MarshalIndent(searchResults, "", "  ")
	log.Printf("gitlab_search_code工具执行成功 - 找到 %d 个结果", len(searchResults))
	
	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabFileContent 执行GitLab文件内容获取
func executeGitLabFileContent(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := args["file_path"].(string)
	if !ok {
		log.Printf("gitlab_file_content工具执行失败 - file_path参数缺失或类型错误")
		return GitLabMCPResult{Error: "file_path参数缺失或类型错误"}
	}

	ref, _ := args["ref"].(string)
	if ref == "" {
		ref = "main" // 默认分支
	}

	log.Printf("gitlab_file_content工具执行 - 文件路径: %s, 分支: %s", filePath, ref)

	// 获取文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: &ref,
	})
	if err != nil {
		log.Printf("gitlab_file_content工具执行失败 - 获取文件失败: %v", err)
		return GitLabMCPResult{Error: fmt.Sprintf("获取文件失败: %v", err)}
	}

	// 检查文件编码
	var content string
	if file.Encoding == "base64" {
		// 解码Base64内容
		decodedBytes, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			log.Printf("gitlab_file_content工具执行失败 - Base64解码失败: %v", err)
			return GitLabMCPResult{Error: fmt.Sprintf("Base64解码失败: %v", err)}
		}
		content = string(decodedBytes)
		log.Printf("gitlab_file_content工具执行 - 成功解码Base64内容")
	} else {
		content = file.Content
	}

	log.Printf("gitlab_file_content工具执行成功 - 文件大小: %d 字节, 编码: %s", len(content), file.Encoding)
	return GitLabMCPResult{Content: content}
}

// executeGitLabProjectFiles 执行GitLab项目文件列表
func executeGitLabProjectFiles(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	path, _ := args["path"].(string)
	ref, _ := args["ref"].(string)
	if ref == "" {
		ref = "main" // 默认分支
	}

	log.Printf("gitlab_project_files工具执行 - 路径: %s, 分支: %s", path, ref)

	// 获取文件列表
	tree, _, err := git.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
		Path: &path,
		Ref:  &ref,
	})
	if err != nil {
		log.Printf("gitlab_project_files工具执行失败 - 获取文件列表失败: %v", err)
		return GitLabMCPResult{Error: fmt.Sprintf("获取文件列表失败: %v", err)}
	}

	// 格式化文件列表
	var files []map[string]interface{}
	for _, item := range tree {
		files = append(files, map[string]interface{}{
			"name":     item.Name,
			"path":     item.Path,
			"type":     item.Type,
			"mode":     item.Mode,
		})
	}

	resultJSON, _ := json.MarshalIndent(files, "", "  ")
	log.Printf("gitlab_project_files工具执行成功 - 找到 %d 个文件", len(files))
	
	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabCommitHistory 执行GitLab提交历史
func executeGitLabCommitHistory(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	since, _ := args["since"].(string)
	until, _ := args["until"].(string)
	author, _ := args["author"].(string)
	path, _ := args["path"].(string)

	log.Printf("gitlab_commit_history工具执行 - since: %s, until: %s, author: %s, path: %s", since, until, author, path)

	// 构建选项
	opts := &gitlab.ListCommitsOptions{}
	if path != "" {
		opts.Path = &path
	}
	// 注意：GitLab API的Since和Until参数可能需要时间格式转换
	// 这里简化处理，只使用Path参数

	// 获取提交历史
	commits, _, err := git.Commits.ListCommits(projectID, opts)
	if err != nil {
		log.Printf("gitlab_commit_history工具执行失败 - 获取提交历史失败: %v", err)
		return GitLabMCPResult{Error: fmt.Sprintf("获取提交历史失败: %v", err)}
	}

	// 格式化提交历史
	var commitList []map[string]interface{}
	for _, commit := range commits {
		commitInfo := map[string]interface{}{
			"id":      commit.ID,
			"title":   commit.Title,
			"author":  commit.AuthorName,
			"date":    commit.CreatedAt,
			"message": commit.Message,
		}
		commitList = append(commitList, commitInfo)
	}

	resultJSON, _ := json.MarshalIndent(commitList, "", "  ")
	log.Printf("gitlab_commit_history工具执行成功 - 找到 %d 个提交", len(commitList))
	
	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabMRChanges 执行GitLab MR变更详情
func executeGitLabMRChanges(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	mrIID, ok := args["mr_iid"].(float64) // JSON中的数字会被解析为float64
	if !ok {
		log.Printf("gitlab_mr_changes工具执行失败 - mr_iid参数缺失或类型错误")
		return GitLabMCPResult{Error: "mr_iid参数缺失或类型错误"}
	}

	log.Printf("gitlab_mr_changes工具执行 - MR IID: %d", int(mrIID))

	// 获取MR变更详情
	changes, _, err := git.MergeRequests.GetMergeRequestChanges(projectID, int(mrIID), &gitlab.GetMergeRequestChangesOptions{})
	if err != nil {
		log.Printf("gitlab_mr_changes工具执行失败 - 获取MR变更失败: %v", err)
		return GitLabMCPResult{Error: fmt.Sprintf("获取MR变更失败: %v", err)}
	}

	// 格式化变更信息
	var changeList []map[string]interface{}
	for _, change := range changes.Changes {
		changeInfo := map[string]interface{}{
			"old_path": change.OldPath,
			"new_path": change.NewPath,
			"diff":     change.Diff,
		}
		changeList = append(changeList, changeInfo)
	}

	resultJSON, _ := json.MarshalIndent(changeList, "", "  ")
	log.Printf("gitlab_mr_changes工具执行成功 - 找到 %d 个变更", len(changeList))
	
	return GitLabMCPResult{Content: string(resultJSON)}
}

// GetAvailableGitLabTools 获取可用的GitLab MCP工具列表
func GetAvailableGitLabTools() []GitLabMCPTool {
	return GitLabMCPTools
} 