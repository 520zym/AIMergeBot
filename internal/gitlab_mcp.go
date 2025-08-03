package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/xanzy/go-gitlab"
)

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

// GitLabMCPTools 定义基于GitLab API的MCP工具（扩展版，包含更多核心工具）
var GitLabMCPTools = []GitLabMCPTool{
	{
		Name:        "gitlab_file_content",
		Description: "获取GitLab仓库中指定文件的完整内容，用于分析函数定义、变量声明、导入等上下文信息",
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
		Name:        "gitlab_file_info",
		Description: "获取GitLab仓库中指定文件的基本信息（行数、大小、类型等），用于了解文件结构后再进行详细分析",
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
		Name:        "gitlab_search_code",
		Description: "在GitLab仓库中搜索指定的文本或模式，用于查找相关函数调用、变量使用、安全模式等",
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
		Name:        "gitlab_context_analysis",
		Description: "分析代码片段的上下文关系，包括前后代码、函数调用、数据流等，用于理解代码逻辑和潜在风险",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "文件路径",
				},
				"line_number": map[string]interface{}{
					"type":        "integer",
					"description": "行号",
				},
				"context_size": map[string]interface{}{
					"type":        "integer",
					"description": "上下文行数（可选，默认为5）",
				},
			},
			"required": []string{"file_path", "line_number"},
		},
	},
	{
		Name:        "gitlab_function_analysis",
		Description: "分析特定函数的完整定义、调用关系、参数传递、返回值处理等，用于深入理解函数的安全风险",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "文件路径",
				},
				"function_name": map[string]interface{}{
					"type":        "string",
					"description": "函数名称",
				},
				"include_calls": map[string]interface{}{
					"type":        "boolean",
					"description": "是否包含函数调用位置（可选，默认为true）",
				},
			},
			"required": []string{"file_path", "function_name"},
		},
	},
	{
		Name:        "gitlab_dependency_analysis",
		Description: "分析项目的依赖关系，包括导入的包、第三方库、版本信息等，用于识别依赖相关的安全风险",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "依赖文件路径（如go.mod、package.json、requirements.txt）",
				},
				"analysis_type": map[string]interface{}{
					"type":        "string",
					"description": "分析类型（dependencies、versions、security）",
				},
			},
			"required": []string{"file_path"},
		},
	},
	{
		Name:        "gitlab_security_pattern_search",
		Description: "搜索特定的安全模式，如SQL注入、XSS、命令注入、路径遍历等漏洞的常见代码模式",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pattern_type": map[string]interface{}{
					"type":        "string",
					"description": "安全模式类型（sql_injection、xss、command_injection、path_traversal、ssrf、auth_bypass）",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（可选）",
				},
				"severity": map[string]interface{}{
					"type":        "string",
					"description": "严重程度过滤（high、medium、low）",
				},
			},
			"required": []string{"pattern_type"},
		},
	},
}

// GitLabMCPExecutor 执行基于GitLab API的MCP工具调用
func GitLabMCPExecutor(call GitLabMCPCall, git *gitlab.Client, projectID int) GitLabMCPResult {
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
		result = executeGitLabSearchCode(call.Arguments, git, projectID)
	case "gitlab_file_content":
		result = executeGitLabFileContent(call.Arguments, git, projectID)
	case "gitlab_file_info":
		result = executeGitLabFileInfo(call.Arguments, git, projectID)
	case "gitlab_context_analysis":
		result = executeGitLabContextAnalysis(call.Arguments, git, projectID)
	case "gitlab_function_analysis":
		result = executeGitLabFunctionAnalysis(call.Arguments, git, projectID)
	case "gitlab_dependency_analysis":
		result = executeGitLabDependencyAnalysis(call.Arguments, git, projectID)
	case "gitlab_security_pattern_search":
		result = executeGitLabSecurityPatternSearch(call.Arguments, git, projectID)
	default:
		log.Printf("GitLab MCP工具调用失败 - 未知工具: %s", call.ToolName)
		result = GitLabMCPResult{
			Error: fmt.Sprintf("未知工具: %s", call.ToolName),
		}
	}

	if result.Error != "" {
		log.Printf("GitLab MCP工具调用失败 - 工具名: %s, 错误: %s", call.ToolName, result.Error)
	} else {
		log.Printf("GitLab MCP工具调用成功 - 工具名: %s, 输出长度: %d", call.ToolName, len(result.Content))
	}

	return result
}

// executeGitLabSearchCode 执行代码搜索
func executeGitLabSearchCode(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	query, ok := args["query"].(string)
	if !ok || query == "" {
		return GitLabMCPResult{Error: "query参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)

	// 获取项目信息
	_, _, err := git.Projects.GetProject(projectID, &gitlab.GetProjectOptions{})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("获取项目信息失败: %v", err)}
	}

	// 获取项目文件列表
	tree, _, err := git.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
		Recursive: gitlab.Bool(true),
		Ref:       gitlab.String("main"),
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("获取文件列表失败: %v", err)}
	}

	// 搜索匹配的文件
	var searchResults []map[string]interface{}
	for _, item := range tree {
		// 跳过目录
		if item.Type == "tree" {
			continue
		}

		// 检查文件类型过滤
		if fileType != "" && !strings.HasSuffix(item.Path, "."+fileType) {
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
			continue
		}

		// 获取文件内容进行搜索
		file, _, err := git.RepositoryFiles.GetFile(projectID, item.Path, &gitlab.GetFileOptions{
			Ref: gitlab.String("main"),
		})
		if err != nil {
			continue
		}

		// 解码Base64内容
		content, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			continue
		}

		// 在文件内容中搜索（不区分大小写）
		contentLower := strings.ToLower(string(content))
		queryLower := strings.ToLower(query)

		if strings.Contains(contentLower, queryLower) {
			// 找到匹配，提取上下文
			lines := strings.Split(string(content), "\n")
			var contextLines []string
			for i, line := range lines {
				lineLower := strings.ToLower(line)
				if strings.Contains(lineLower, queryLower) {
					// 添加上下文行
					start := max(0, i-2)
					end := min(len(lines), i+3)
					for j := start; j < end; j++ {
						contextLines = append(contextLines, fmt.Sprintf("%d: %s", j+1, lines[j]))
					}
					break
				}
			}

			searchResults = append(searchResults, map[string]interface{}{
				"file_path": item.Path,
				"content":   strings.Join(contextLines, "\n"),
				"line":      "找到匹配",
			})
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"query":   query,
		"results": searchResults,
		"count":   len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabFileContent 执行文件内容获取
func executeGitLabFileContent(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := args["file_path"].(string)
	if !ok || filePath == "" {
		return GitLabMCPResult{Error: "file_path参数缺失或类型错误"}
	}

	ref, _ := args["ref"].(string)
	if ref == "" {
		ref = "main" // 默认分支
	}

	// 获取文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: &ref,
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("获取文件失败: %v", err)}
	}

	// 解码Base64内容
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("Base64解码失败: %v", err)}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"file_path": filePath,
		"ref":       ref,
		"content":   string(content),
		"size":      len(content),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabFileInfo 执行文件信息获取
func executeGitLabFileInfo(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := args["file_path"].(string)
	if !ok || filePath == "" {
		return GitLabMCPResult{Error: "file_path参数缺失或类型错误"}
	}

	ref := "main" // 默认分支
	if r, ok := args["ref"].(string); ok && r != "" {
		ref = r
	}

	// 获取项目信息
	_, _, err := git.Projects.GetProject(projectID, &gitlab.GetProjectOptions{})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("获取项目信息失败: %v", err)}
	}

	// 获取文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: gitlab.String(ref),
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("无法找到文件 %s，请检查文件路径是否正确", filePath)}
	}

	// 解码Base64内容以计算行数
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("Base64解码失败: %v", err)}
	}

	// 计算行数
	lines := strings.Split(string(content), "\n")
	lineCount := len(lines)

	// 获取文件扩展名
	fileExt := ""
	if lastDot := strings.LastIndex(filePath, "."); lastDot != -1 {
		fileExt = filePath[lastDot+1:]
	}

	// 判断文件类型
	fileType := "unknown"
	codeExtensions := map[string]string{
		"go": "Go", "py": "Python", "js": "JavaScript", "ts": "TypeScript",
		"java": "Java", "c": "C", "cpp": "C++", "h": "Header", "hpp": "C++ Header",
		"cs": "C#", "php": "PHP", "rb": "Ruby", "rs": "Rust", "swift": "Swift",
		"kt": "Kotlin", "scala": "Scala", "sh": "Shell", "bash": "Bash",
		"yaml": "YAML", "yml": "YAML", "json": "JSON", "xml": "XML",
		"html": "HTML", "css": "CSS", "md": "Markdown", "txt": "Text",
	}
	if lang, exists := codeExtensions[fileExt]; exists {
		fileType = lang
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"file_path":   filePath,
		"ref":         ref,
		"file_name":   file.FileName,
		"file_size":   file.Size,
		"line_count":  lineCount,
		"file_type":   fileType,
		"file_ext":    fileExt,
		"encoding":    file.Encoding,
		"content_preview": func() string {
			if len(content) > 200 {
				return string(content[:200]) + "..."
			}
			return string(content)
		}(),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// GetAvailableGitLabTools 获取可用的GitLab MCP工具列表
func GetAvailableGitLabTools() []GitLabMCPTool {
	return GitLabMCPTools
}

// executeGitLabContextAnalysis 执行上下文分析
func executeGitLabContextAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := args["file_path"].(string)
	if !ok || filePath == "" {
		return GitLabMCPResult{Error: "file_path参数缺失或类型错误"}
	}

	lineNumber, ok := args["line_number"].(float64)
	if !ok {
		return GitLabMCPResult{Error: "line_number参数缺失或类型错误"}
	}

	contextSize := 5 // 默认上下文行数
	if size, ok := args["context_size"].(float64); ok {
		contextSize = int(size)
	}

	// 获取项目信息
	_, _, err := git.Projects.GetProject(projectID, &gitlab.GetProjectOptions{})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("获取项目信息失败: %v", err)}
	}

	// 获取文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: gitlab.String("main"),
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("无法找到文件 %s，请检查文件路径是否正确", filePath)}
	}

	// 解码Base64内容
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("Base64解码失败: %v", err)}
	}

	// 分析上下文
	lines := strings.Split(string(content), "\n")
	lineIndex := int(lineNumber) - 1
	totalLines := len(lines)

	// 智能行号调整：如果请求的行号超出范围，提供更好的处理策略
	var adjustedLineNumber int
	var adjustmentInfo string
	var shouldReturnFullContent bool
	
	if lineIndex < 0 {
		// 如果请求的行号小于1，返回文件开头的内容
		adjustedLineNumber = 1
		lineIndex = 0
		adjustmentInfo = fmt.Sprintf("请求的行号 %d 小于1，已调整为第1行", int(lineNumber))
		shouldReturnFullContent = totalLines <= 20 // 如果文件很小，返回完整内容
	} else if lineIndex >= totalLines {
		// 如果请求的行号超出范围，返回文件末尾的内容
		adjustedLineNumber = totalLines
		lineIndex = totalLines - 1
		adjustmentInfo = fmt.Sprintf("请求的行号 %d 超出文件范围（文件共%d行），已调整为最后一行", int(lineNumber), totalLines)
		shouldReturnFullContent = totalLines <= 20 // 如果文件很小，返回完整内容
	} else {
		adjustedLineNumber = int(lineNumber)
		shouldReturnFullContent = false
	}

	// 构建结果
	resultData := map[string]interface{}{
		"file_path":     filePath,
		"line_number":   adjustedLineNumber,
		"context_size":  contextSize,
		"total_lines":   totalLines,
	}

	// 如果有行号调整，添加调整信息
	if adjustmentInfo != "" {
		resultData["adjustment_info"] = adjustmentInfo
		resultData["original_line_number"] = int(lineNumber)
	}

	// 根据情况决定返回的内容
	if shouldReturnFullContent {
		// 对于小文件或行号调整的情况，返回完整内容
		resultData["context"] = string(content)
		resultData["context_start"] = 1
		resultData["context_end"] = totalLines
		resultData["target_line"] = lines[lineIndex]
		resultData["full_content_returned"] = true
		resultData["reason"] = "文件较小或行号调整，返回完整内容以便分析"
	} else {
		// 正常情况，返回指定行的上下文
		start := max(0, lineIndex-contextSize)
		end := min(len(lines), lineIndex+contextSize+1)

		contextLines := lines[start:end]
		contextContent := strings.Join(contextLines, "\n")

		resultData["context"] = contextContent
		resultData["context_start"] = start + 1
		resultData["context_end"] = end
		resultData["target_line"] = lines[lineIndex]
		resultData["full_content_returned"] = false
	}

	resultJSON, _ := json.Marshal(resultData)

	return GitLabMCPResult{Content: string(resultJSON)}
}

// 辅助函数
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
} 

// executeGitLabFunctionAnalysis 执行函数分析
func executeGitLabFunctionAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := args["file_path"].(string)
	if !ok || filePath == "" {
		return GitLabMCPResult{Error: "file_path参数缺失或类型错误"}
	}

	functionName, ok := args["function_name"].(string)
	if !ok || functionName == "" {
		return GitLabMCPResult{Error: "function_name参数缺失或类型错误"}
	}

	includeCalls := true
	if calls, ok := args["include_calls"].(bool); ok {
		includeCalls = calls
	}

	// 获取文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: gitlab.String("main"),
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("无法找到文件 %s，请检查文件路径是否正确", filePath)}
	}

	// 解码Base64内容
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("Base64解码失败: %v", err)}
	}

	// 分析函数
	lines := strings.Split(string(content), "\n")
	var functionInfo map[string]interface{}
	var callLocations []map[string]interface{}

	// 查找函数定义
	for i, line := range lines {
		if strings.Contains(line, "func "+functionName) || strings.Contains(line, "func("+functionName) {
			// 找到函数定义
			startLine := i + 1
			endLine := findFunctionEnd(lines, i)
			
			functionContent := strings.Join(lines[startLine-1:endLine], "\n")
			
			functionInfo = map[string]interface{}{
				"function_name": functionName,
				"start_line":    startLine,
				"end_line":      endLine,
				"definition":    functionContent,
				"parameters":    extractFunctionParameters(line),
				"return_type":   extractReturnType(line),
			}
			break
		}
	}

	// 查找函数调用
	if includeCalls {
		for i, line := range lines {
			if strings.Contains(line, functionName+"(") && !strings.Contains(line, "func "+functionName) {
				callLocations = append(callLocations, map[string]interface{}{
					"line_number": i + 1,
					"context":     getLineContext(lines, i, 2),
					"call":        strings.TrimSpace(line),
				})
			}
		}
	}

	resultData := map[string]interface{}{
		"file_path": filePath,
		"function":  functionInfo,
		"calls":     callLocations,
		"total_calls": len(callLocations),
	}

	resultJSON, _ := json.Marshal(resultData)
	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabSecurityPatternSearch 执行安全模式搜索
func executeGitLabSecurityPatternSearch(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	patternType, ok := args["pattern_type"].(string)
	if !ok || patternType == "" {
		return GitLabMCPResult{Error: "pattern_type参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)
	severity, _ := args["severity"].(string)

	// 定义安全模式
	securityPatterns := map[string][]string{
		"sql_injection": {
			"SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "UNION",
			"query(", "exec(", "Execute(", "QueryRow(",
		},
		"xss": {
			"innerHTML", "outerHTML", "document.write", "eval(",
			"<script>", "javascript:", "onload=", "onerror=",
		},
		"command_injection": {
			"exec(", "system(", "shell_exec(", "passthru(",
			"os.Exec", "subprocess", "Process.Start",
		},
		"path_traversal": {
			"../", "..\\", "~", "/etc/", "C:\\",
			"file://", "file:///",
		},
		"ssrf": {
			"http.Get", "http.Post", "fetch(", "axios.get",
			"urllib.request", "requests.get",
		},
		"auth_bypass": {
			"admin", "root", "password", "token", "secret",
			"bypass", "skip", "ignore",
		},
	}

	patterns, exists := securityPatterns[patternType]
	if !exists {
		return GitLabMCPResult{Error: fmt.Sprintf("不支持的安全模式类型: %s", patternType)}
	}

	// 搜索匹配的文件
	var searchResults []map[string]interface{}
	
	// 获取项目文件列表
	tree, _, err := git.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
		Recursive: gitlab.Bool(true),
		Ref:       gitlab.String("main"),
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("获取文件列表失败: %v", err)}
	}

	for _, item := range tree {
		if item.Type == "tree" {
			continue
		}

		// 检查文件类型过滤
		if fileType != "" && !strings.HasSuffix(item.Path, "."+fileType) {
			continue
		}

		// 获取文件内容
		file, _, err := git.RepositoryFiles.GetFile(projectID, item.Path, &gitlab.GetFileOptions{
			Ref: gitlab.String("main"),
		})
		if err != nil {
			continue
		}

		// 解码Base64内容
		content, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			continue
		}

		// 在文件内容中搜索安全模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 1),
						"severity":    determineSeverity(pattern, patternType),
					})
				}
			}
		}
	}

	// 根据严重程度过滤
	if severity != "" {
		var filteredResults []map[string]interface{}
		for _, result := range searchResults {
			if result["severity"] == severity {
				filteredResults = append(filteredResults, result)
			}
		}
		searchResults = filteredResults
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"pattern_type":   patternType,
		"file_type":      fileType,
		"severity":       severity,
		"results":        searchResults,
		"total_results":  len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabDependencyAnalysis 执行依赖分析
func executeGitLabDependencyAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := args["file_path"].(string)
	if !ok || filePath == "" {
		return GitLabMCPResult{Error: "file_path参数缺失或类型错误"}
	}

	analysisType, _ := args["analysis_type"].(string)
	if analysisType == "" {
		analysisType = "dependencies"
	}

	// 获取依赖文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: gitlab.String("main"),
	})
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("无法找到文件 %s，请检查文件路径是否正确", filePath)}
	}

	// 解码Base64内容
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return GitLabMCPResult{Error: fmt.Sprintf("Base64解码失败: %v", err)}
	}

	// 根据文件类型分析依赖
	var dependencies []map[string]interface{}
	var securityIssues []map[string]interface{}

	lines := strings.Split(string(content), "\n")
	
	if strings.HasSuffix(filePath, "go.mod") {
		// Go 模块依赖分析
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "require ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					dependencies = append(dependencies, map[string]interface{}{
						"name":    parts[1],
						"version": parts[2],
						"type":    "go",
					})
				}
			}
		}
	} else if strings.HasSuffix(filePath, "package.json") {
		// Node.js 依赖分析
		var packageData map[string]interface{}
		if err := json.Unmarshal(content, &packageData); err == nil {
			if deps, ok := packageData["dependencies"].(map[string]interface{}); ok {
				for name, version := range deps {
					dependencies = append(dependencies, map[string]interface{}{
						"name":    name,
						"version": version,
						"type":    "npm",
					})
				}
			}
		}
	} else if strings.HasSuffix(filePath, "requirements.txt") {
		// Python 依赖分析
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				parts := strings.Split(line, "==")
				if len(parts) == 2 {
					dependencies = append(dependencies, map[string]interface{}{
						"name":    parts[0],
						"version": parts[1],
						"type":    "pip",
					})
				}
			}
		}
	}

	// 分析安全风险
	for _, dep := range dependencies {
		// 这里可以集成漏洞数据库查询
		// 目前返回基本的安全检查建议
		securityIssues = append(securityIssues, map[string]interface{}{
			"dependency": dep["name"],
			"version":    dep["version"],
			"risk":       "medium", // 默认风险等级
			"advice":     "建议检查依赖的已知漏洞",
		})
	}

	resultData := map[string]interface{}{
		"file_path":       filePath,
		"analysis_type":   analysisType,
		"dependencies":    dependencies,
		"security_issues": securityIssues,
		"total_deps":      len(dependencies),
		"total_issues":    len(securityIssues),
	}

	resultJSON, _ := json.Marshal(resultData)
	return GitLabMCPResult{Content: string(resultJSON)}
}

// 辅助函数
func findFunctionEnd(lines []string, startIndex int) int {
	braceCount := 0
	inFunction := false
	
	for i := startIndex; i < len(lines); i++ {
		line := lines[i]
		
		if strings.Contains(line, "func ") && !inFunction {
			inFunction = true
		}
		
		if inFunction {
			braceCount += strings.Count(line, "{")
			braceCount -= strings.Count(line, "}")
			
			if braceCount == 0 && inFunction {
				return i + 1
			}
		}
	}
	
	return len(lines)
}

func extractFunctionParameters(line string) []string {
	// 简单的参数提取逻辑
	if strings.Contains(line, "(") && strings.Contains(line, ")") {
		start := strings.Index(line, "(")
		end := strings.Index(line, ")")
		if start < end {
			params := strings.TrimSpace(line[start+1 : end])
			if params != "" {
				return strings.Split(params, ",")
			}
		}
	}
	return []string{}
}

func extractReturnType(line string) string {
	// 简单的返回类型提取逻辑
	if strings.Contains(line, ")") && strings.Contains(line, "{") {
		parts := strings.Split(line, ")")
		if len(parts) > 1 {
			afterParen := strings.TrimSpace(parts[1])
			if strings.Contains(afterParen, "{") {
				returnType := strings.TrimSpace(afterParen[:strings.Index(afterParen, "{")])
				return returnType
			}
		}
	}
	return ""
}

func getLineContext(lines []string, lineIndex, contextSize int) string {
	start := max(0, lineIndex-contextSize)
	end := min(len(lines), lineIndex+contextSize+1)
	return strings.Join(lines[start:end], "\n")
}

func determineSeverity(pattern, patternType string) string {
	highRiskPatterns := map[string][]string{
		"sql_injection": {"SELECT", "INSERT", "UPDATE", "DELETE"},
		"command_injection": {"exec(", "system(", "shell_exec("},
		"ssrf": {"http.Get", "http.Post"},
	}
	
	if patterns, exists := highRiskPatterns[patternType]; exists {
		for _, highPattern := range patterns {
			if strings.Contains(strings.ToLower(pattern), strings.ToLower(highPattern)) {
				return "high"
			}
		}
	}
	
	return "medium"
}

 