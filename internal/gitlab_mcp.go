package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
				"context_lines": map[string]interface{}{
					"type":        "integer",
					"description": "上下文行数（可选，默认5行）",
				},
			},
			"required": []string{"file_path", "line_number"},
		},
	},
	{
		Name:        "gitlab_function_analysis",
		Description: "分析特定函数的完整定义、调用关系、参数传递等，用于深入理解函数的安全性和潜在风险",
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
					"description": "是否包含函数调用信息（可选，默认true）",
				},
			},
			"required": []string{"file_path", "function_name"},
		},
	},
	{
		Name:        "gitlab_recursive_function_analysis",
		Description: "递归分析函数调用链，追踪函数间的调用关系，深入分析被调用函数的实现，用于发现通过调用链传播的安全漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "起始文件路径",
				},
				"function_name": map[string]interface{}{
					"type":        "string",
					"description": "起始函数名称",
				},
				"max_depth": map[string]interface{}{
					"type":        "integer",
					"description": "最大递归深度（可选，默认3层）",
				},
				"include_security_analysis": map[string]interface{}{
					"type":        "boolean",
					"description": "是否包含安全分析（可选，默认true）",
				},
				"analyze_cross_file_calls": map[string]interface{}{
					"type":        "boolean",
					"description": "是否分析跨文件调用（可选，默认true）",
				},
			},
			"required": []string{"file_path", "function_name"},
		},
	},
	{
		Name:        "gitlab_security_pattern_search",
		Description: "搜索特定的安全漏洞模式（SQL注入、XSS、命令注入等），用于快速识别潜在的安全风险",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pattern_type": map[string]interface{}{
					"type":        "string",
					"description": "安全模式类型（sql_injection、xss、command_injection、path_traversal、ssrf、auth_bypass等）",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（可选）",
				},
				"severity": map[string]interface{}{
					"type":        "string",
					"description": "严重程度过滤（high、medium、low，可选）",
				},
			},
			"required": []string{"pattern_type"},
		},
	},
	{
		Name:        "gitlab_dependency_analysis",
		Description: "分析项目依赖的安全风险，包括第三方库的漏洞、版本问题等",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "依赖文件路径（如go.mod、package.json、requirements.txt等）",
				},
				"analysis_type": map[string]interface{}{
					"type":        "string",
					"description": "分析类型（dependencies、security、versions，可选）",
				},
			},
			"required": []string{"file_path"},
		},
	},
	{
		Name:        "gitlab_authentication_analysis",
		Description: "分析认证和授权机制，包括登录流程、权限检查、会话管理等，用于识别认证绕过和权限提升漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"search_pattern": map[string]interface{}{
					"type":        "string",
					"description": "搜索模式（auth、login、session、token、permission等）",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（可选）",
				},
			},
			"required": []string{"search_pattern"},
		},
	},
	{
		Name:        "gitlab_input_validation_analysis",
		Description: "分析输入验证和过滤机制，包括参数验证、输入过滤、输出编码等，用于识别注入漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"validation_type": map[string]interface{}{
					"type":        "string",
					"description": "验证类型（input、output、filter、encode等）",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（可选）",
				},
			},
			"required": []string{"validation_type"},
		},
	},
	{
		Name:        "gitlab_business_logic_analysis",
		Description: "分析业务逻辑的安全性，包括业务流程、规则验证、并发控制等，用于识别业务逻辑漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"logic_type": map[string]interface{}{
					"type":        "string",
					"description": "逻辑类型（business、concurrency、race_condition、bypass等）",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（可选）",
				},
			},
			"required": []string{"logic_type"},
		},
	},
	{
		Name:        "gitlab_data_flow_analysis",
		Description: "追踪数据流，分析敏感数据的传输、存储、处理过程，用于识别数据泄露和隐私问题",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"data_type": map[string]interface{}{
					"type":        "string",
					"description": "数据类型（sensitive、personal、credential、token等）",
				},
				"flow_type": map[string]interface{}{
					"type":        "string",
					"description": "流类型（input、output、storage、transmission等）",
				},
			},
			"required": []string{"data_type"},
		},
	},
	{
		Name:        "gitlab_api_endpoint_analysis",
		Description: "分析API端点的安全性，包括端点定义、参数处理、权限控制等，用于识别API安全漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"endpoint_type": map[string]interface{}{
					"type":        "string",
					"description": "端点类型（rest、graphql、rpc、websocket等）",
				},
				"security_aspect": map[string]interface{}{
					"type":        "string",
					"description": "安全方面（auth、input、output、rate_limit等）",
				},
			},
			"required": []string{"endpoint_type"},
		},
	},
	{
		Name:        "gitlab_error_handling_analysis",
		Description: "分析错误处理机制的安全性，包括异常处理、错误信息、调试信息等，用于识别信息泄露",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"error_type": map[string]interface{}{
					"type":        "string",
					"description": "错误类型（exception、validation、system、debug等）",
				},
				"file_type": map[string]interface{}{
					"type":        "string",
					"description": "文件类型过滤（可选）",
				},
			},
			"required": []string{"error_type"},
		},
	},
	{
		Name:        "gitlab_file_operation_analysis",
		Description: "分析文件操作的安全性，包括文件上传、下载、读写、权限控制等，用于识别文件操作漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"operation_type": map[string]interface{}{
					"type":        "string",
					"description": "操作类型（upload、download、read、write、delete等）",
				},
				"security_aspect": map[string]interface{}{
					"type":        "string",
					"description": "安全方面（path、permission、validation、encoding等）",
				},
			},
			"required": []string{"operation_type"},
		},
	},
	{
		Name:        "gitlab_network_operation_analysis",
		Description: "分析网络操作的安全性，包括HTTP请求、网络调用、URL处理等，用于识别SSRF和网络相关漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"network_type": map[string]interface{}{
					"type":        "string",
					"description": "网络类型（http、https、tcp、udp、websocket等）",
				},
				"security_aspect": map[string]interface{}{
					"type":        "string",
					"description": "安全方面（url、protocol、certificate、proxy等）",
				},
			},
			"required": []string{"network_type"},
		},
	},
	{
		Name:        "gitlab_config_analysis",
		Description: "分析配置文件中的安全问题，包括敏感配置、权限设置、安全选项等，用于识别配置漏洞",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"config_type": map[string]interface{}{
					"type":        "string",
					"description": "配置类型（security、database、network、application等）",
				},
				"file_pattern": map[string]interface{}{
					"type":        "string",
					"description": "文件模式（*.conf、*.yml、*.json、*.env等）",
				},
			},
			"required": []string{"config_type"},
		},
	},
}

// GitLabMCPExecutor 执行GitLab MCP工具调用
func GitLabMCPExecutor(call GitLabMCPCall, git *gitlab.Client, projectID int) GitLabMCPResult {
	switch call.ToolName {
	case "gitlab_search_code":
		return executeGitLabSearchCode(call.Arguments, git, projectID)
	case "gitlab_file_content":
		return executeGitLabFileContent(call.Arguments, git, projectID)
	case "gitlab_file_info":
		return executeGitLabFileInfo(call.Arguments, git, projectID)
	case "gitlab_context_analysis":
		return executeGitLabContextAnalysis(call.Arguments, git, projectID)
	case "gitlab_function_analysis":
		return executeGitLabFunctionAnalysis(call.Arguments, git, projectID)
	case "gitlab_security_pattern_search":
		return executeGitLabSecurityPatternSearch(call.Arguments, git, projectID)
	case "gitlab_dependency_analysis":
		return executeGitLabDependencyAnalysis(call.Arguments, git, projectID)
	case "gitlab_authentication_analysis":
		return executeGitLabAuthenticationAnalysis(call.Arguments, git, projectID)
	case "gitlab_input_validation_analysis":
		return executeGitLabInputValidationAnalysis(call.Arguments, git, projectID)
	case "gitlab_business_logic_analysis":
		return executeGitLabBusinessLogicAnalysis(call.Arguments, git, projectID)
	case "gitlab_data_flow_analysis":
		return executeGitLabDataFlowAnalysis(call.Arguments, git, projectID)
	case "gitlab_api_endpoint_analysis":
		return executeGitLabAPIEndpointAnalysis(call.Arguments, git, projectID)
	case "gitlab_error_handling_analysis":
		return executeGitLabErrorHandlingAnalysis(call.Arguments, git, projectID)
	case "gitlab_file_operation_analysis":
		return executeGitLabFileOperationAnalysis(call.Arguments, git, projectID)
	case "gitlab_network_operation_analysis":
		return executeGitLabNetworkOperationAnalysis(call.Arguments, git, projectID)
	case "gitlab_config_analysis":
		return executeGitLabConfigAnalysis(call.Arguments, git, projectID)
	case "gitlab_recursive_function_analysis":
		return executeGitLabRecursiveFunctionAnalysis(call.Arguments, git, projectID)
	default:
		return GitLabMCPResult{Error: fmt.Sprintf("未知的工具: %s", call.ToolName)}
	}
}

// GetStringParam 获取字符串参数，支持多种参数名变体
func GetStringParam(args map[string]interface{}, paramNames ...string) (string, bool) {
	for _, name := range paramNames {
		if value, ok := args[name].(string); ok && value != "" {
			return value, true
		}
	}
	return "", false
}

// executeGitLabSearchCode 执行代码搜索
func executeGitLabSearchCode(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	// 支持多种参数名：query, search_term, searchTerm
	query, ok := GetStringParam(args, "query", "search_term", "searchTerm")
	if !ok {
		return GitLabMCPResult{Error: "query/search_term/searchTerm参数缺失或类型错误"}
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
	filePath, ok := GetStringParam(args, "file_path", "filePath", "filepath")
	if !ok {
		return GitLabMCPResult{Error: "file_path/filePath/filepath参数缺失或类型错误"}
	}

	ref, _ := GetStringParam(args, "ref", "branch", "reference")
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
	filePath, ok := GetStringParam(args, "file_path", "filePath", "filepath")
	if !ok {
		return GitLabMCPResult{Error: "file_path/filePath/filepath参数缺失或类型错误"}
	}

	ref := "main" // 默认分支
	if r, ok := GetStringParam(args, "ref", "branch", "reference"); ok {
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
	filePath, ok := GetStringParam(args, "file_path", "filePath", "filepath")
	if !ok {
		return GitLabMCPResult{Error: "file_path/filePath/filepath参数缺失或类型错误"}
	}

	lineNumber, ok := args["line_number"].(float64)
	if !ok {
		return GitLabMCPResult{Error: "line_number参数缺失或类型错误"}
	}

	contextSize := 5 // 默认上下文行数
	if size, ok := args["context_lines"].(float64); ok {
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
	filePath, ok := GetStringParam(args, "file_path", "filePath", "filepath")
	if !ok {
		return GitLabMCPResult{Error: "file_path/filePath/filepath参数缺失或类型错误"}
	}

	functionName, ok := GetStringParam(args, "function_name", "functionName", "function")
	if !ok {
		return GitLabMCPResult{Error: "function_name/functionName/function参数缺失或类型错误"}
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
	filePath, ok := GetStringParam(args, "file_path", "filePath", "filepath")
	if !ok {
		return GitLabMCPResult{Error: "file_path/filePath/filepath参数缺失或类型错误"}
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

// executeGitLabAuthenticationAnalysis 执行认证分析
func executeGitLabAuthenticationAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	searchPattern, ok := args["search_pattern"].(string)
	if !ok || searchPattern == "" {
		return GitLabMCPResult{Error: "search_pattern参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)

	// 定义认证相关搜索模式
	authPatterns := map[string][]string{
		"auth": {
			"auth", "authentication", "login", "logout", "signin", "signout",
			"authenticate", "authorize", "authorization", "permission",
		},
		"login": {
			"login", "signin", "authenticate", "password", "username",
			"credential", "session", "token", "jwt", "oauth",
		},
		"session": {
			"session", "cookie", "token", "jwt", "refresh", "expire",
			"timeout", "logout", "signout", "clear",
		},
		"token": {
			"token", "jwt", "bearer", "access_token", "refresh_token",
			"api_key", "secret", "credential",
		},
		"permission": {
			"permission", "role", "admin", "user", "guest", "access",
			"authorize", "authorization", "privilege", "right",
		},
	}

	patterns, exists := authPatterns[searchPattern]
	if !exists {
		// 如果没有预定义模式，使用搜索模式作为关键词
		patterns = []string{searchPattern}
	}

	// 搜索认证相关代码
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

		// 在文件内容中搜索认证模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "authentication",
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"search_pattern": searchPattern,
		"file_type":     fileType,
		"results":       searchResults,
		"total_results": len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabInputValidationAnalysis 执行输入验证分析
func executeGitLabInputValidationAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	validationType, ok := args["validation_type"].(string)
	if !ok || validationType == "" {
		return GitLabMCPResult{Error: "validation_type参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)

	// 定义输入验证相关搜索模式
	validationPatterns := map[string][]string{
		"input": {
			"input", "validate", "validation", "check", "verify",
			"sanitize", "filter", "clean", "escape",
		},
		"output": {
			"output", "encode", "escape", "html", "url", "json",
			"xml", "sql", "javascript", "encodeURIComponent",
		},
		"filter": {
			"filter", "sanitize", "clean", "remove", "replace",
			"strip", "trim", "whitelist", "blacklist",
		},
		"encode": {
			"encode", "escape", "html", "url", "base64", "hex",
			"encodeURIComponent", "encodeURI", "escapeHtml",
		},
	}

	patterns, exists := validationPatterns[validationType]
	if !exists {
		// 如果没有预定义模式，使用验证类型作为关键词
		patterns = []string{validationType}
	}

	// 搜索输入验证相关代码
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

		// 在文件内容中搜索验证模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "input_validation",
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"validation_type": validationType,
		"file_type":      fileType,
		"results":        searchResults,
		"total_results":  len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabBusinessLogicAnalysis 执行业务逻辑分析
func executeGitLabBusinessLogicAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	logicType, ok := args["logic_type"].(string)
	if !ok || logicType == "" {
		return GitLabMCPResult{Error: "logic_type参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)

	// 定义业务逻辑相关搜索模式
	logicPatterns := map[string][]string{
		"business": {
			"business", "logic", "rule", "policy", "workflow",
			"process", "state", "status", "condition",
		},
		"concurrency": {
			"concurrency", "race", "thread", "lock", "mutex",
			"atomic", "synchronize", "parallel", "async",
		},
		"race_condition": {
			"race", "condition", "timing", "order", "sequence",
			"concurrent", "parallel", "thread", "lock",
		},
		"bypass": {
			"bypass", "skip", "ignore", "disable", "override",
			"circumvent", "evade", "avoid", "exclude",
		},
	}

	patterns, exists := logicPatterns[logicType]
	if !exists {
		// 如果没有预定义模式，使用逻辑类型作为关键词
		patterns = []string{logicType}
	}

	// 搜索业务逻辑相关代码
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

		// 在文件内容中搜索业务逻辑模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 3),
						"type":        "business_logic",
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"logic_type":   logicType,
		"file_type":    fileType,
		"results":      searchResults,
		"total_results": len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabDataFlowAnalysis 执行数据流分析
func executeGitLabDataFlowAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	dataType, ok := args["data_type"].(string)
	if !ok || dataType == "" {
		return GitLabMCPResult{Error: "data_type参数缺失或类型错误"}
	}

	flowType, _ := args["flow_type"].(string)

	// 定义数据流相关搜索模式
	dataPatterns := map[string][]string{
		"sensitive": {
			"sensitive", "secret", "password", "token", "key",
			"credential", "private", "confidential", "personal",
		},
		"personal": {
			"personal", "user", "customer", "client", "profile",
			"name", "email", "phone", "address", "id",
		},
		"credential": {
			"credential", "password", "token", "key", "secret",
			"auth", "login", "session", "jwt", "api_key",
		},
		"token": {
			"token", "jwt", "bearer", "access_token", "refresh_token",
			"api_key", "secret", "credential", "session",
		},
	}

	patterns, exists := dataPatterns[dataType]
	if !exists {
		// 如果没有预定义模式，使用数据类型作为关键词
		patterns = []string{dataType}
	}

	// 搜索数据流相关代码
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

		// 在文件内容中搜索数据流模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "data_flow",
						"flow_type":   flowType,
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"data_type":    dataType,
		"flow_type":    flowType,
		"results":      searchResults,
		"total_results": len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabAPIEndpointAnalysis 执行API端点分析
func executeGitLabAPIEndpointAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	endpointType, ok := args["endpoint_type"].(string)
	if !ok || endpointType == "" {
		return GitLabMCPResult{Error: "endpoint_type参数缺失或类型错误"}
	}

	securityAspect, _ := args["security_aspect"].(string)

	// 定义API端点相关搜索模式
	endpointPatterns := map[string][]string{
		"rest": {
			"rest", "api", "endpoint", "route", "handler",
			"get", "post", "put", "delete", "patch",
		},
		"graphql": {
			"graphql", "query", "mutation", "subscription",
			"resolver", "schema", "type", "field",
		},
		"rpc": {
			"rpc", "grpc", "remote", "procedure", "call",
			"service", "method", "function",
		},
		"websocket": {
			"websocket", "ws", "wss", "socket", "connection",
			"real-time", "stream", "event",
		},
	}

	patterns, exists := endpointPatterns[endpointType]
	if !exists {
		// 如果没有预定义模式，使用端点类型作为关键词
		patterns = []string{endpointType}
	}

	// 搜索API端点相关代码
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

		// 在文件内容中搜索API端点模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "api_endpoint",
						"security_aspect": securityAspect,
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"endpoint_type":   endpointType,
		"security_aspect": securityAspect,
		"results":         searchResults,
		"total_results":   len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabErrorHandlingAnalysis 执行错误处理分析
func executeGitLabErrorHandlingAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	errorType, ok := args["error_type"].(string)
	if !ok || errorType == "" {
		return GitLabMCPResult{Error: "error_type参数缺失或类型错误"}
	}

	fileType, _ := args["file_type"].(string)

	// 定义错误处理相关搜索模式
	errorPatterns := map[string][]string{
		"exception": {
			"exception", "error", "catch", "try", "throw",
			"panic", "recover", "fatal", "critical",
		},
		"validation": {
			"validation", "validate", "check", "verify",
			"invalid", "error", "failed", "reject",
		},
		"system": {
			"system", "error", "fatal", "critical", "panic",
			"crash", "abort", "terminate", "exit",
		},
		"debug": {
			"debug", "log", "print", "console", "trace",
			"dump", "debugger", "breakpoint", "inspect",
		},
	}

	patterns, exists := errorPatterns[errorType]
	if !exists {
		// 如果没有预定义模式，使用错误类型作为关键词
		patterns = []string{errorType}
	}

	// 搜索错误处理相关代码
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

		// 在文件内容中搜索错误处理模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "error_handling",
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"error_type":   errorType,
		"file_type":    fileType,
		"results":      searchResults,
		"total_results": len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabFileOperationAnalysis 执行文件操作分析
func executeGitLabFileOperationAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	operationType, ok := args["operation_type"].(string)
	if !ok || operationType == "" {
		return GitLabMCPResult{Error: "operation_type参数缺失或类型错误"}
	}

	securityAspect, _ := args["security_aspect"].(string)

	// 定义文件操作相关搜索模式
	operationPatterns := map[string][]string{
		"upload": {
			"upload", "file", "multipart", "form", "input",
			"save", "store", "write", "create",
		},
		"download": {
			"download", "file", "read", "get", "fetch",
			"retrieve", "load", "open", "stream",
		},
		"read": {
			"read", "file", "open", "load", "get",
			"readFile", "readdir", "stat", "access",
		},
		"write": {
			"write", "file", "save", "create", "update",
			"writeFile", "append", "modify", "change",
		},
		"delete": {
			"delete", "remove", "unlink", "rm", "del",
			"erase", "clear", "purge", "trash",
		},
	}

	patterns, exists := operationPatterns[operationType]
	if !exists {
		// 如果没有预定义模式，使用操作类型作为关键词
		patterns = []string{operationType}
	}

	// 搜索文件操作相关代码
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

		// 在文件内容中搜索文件操作模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "file_operation",
						"security_aspect": securityAspect,
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"operation_type":  operationType,
		"security_aspect": securityAspect,
		"results":         searchResults,
		"total_results":   len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabNetworkOperationAnalysis 执行网络操作分析
func executeGitLabNetworkOperationAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	networkType, ok := args["network_type"].(string)
	if !ok || networkType == "" {
		return GitLabMCPResult{Error: "network_type参数缺失或类型错误"}
	}

	securityAspect, _ := args["security_aspect"].(string)

	// 定义网络操作相关搜索模式
	networkPatterns := map[string][]string{
		"http": {
			"http", "https", "request", "response", "get",
			"post", "put", "delete", "fetch", "axios",
		},
		"https": {
			"https", "ssl", "tls", "certificate", "secure",
			"encrypt", "decrypt", "cipher", "key",
		},
		"tcp": {
			"tcp", "socket", "connection", "port", "bind",
			"listen", "accept", "connect", "send", "receive",
		},
		"udp": {
			"udp", "datagram", "packet", "send", "receive",
			"broadcast", "multicast", "stream",
		},
		"websocket": {
			"websocket", "ws", "wss", "socket", "connection",
			"real-time", "stream", "event", "message",
		},
	}

	patterns, exists := networkPatterns[networkType]
	if !exists {
		// 如果没有预定义模式，使用网络类型作为关键词
		patterns = []string{networkType}
	}

	// 搜索网络操作相关代码
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

		// 在文件内容中搜索网络操作模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "network_operation",
						"security_aspect": securityAspect,
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"network_type":   networkType,
		"security_aspect": securityAspect,
		"results":         searchResults,
		"total_results":   len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// executeGitLabConfigAnalysis 执行配置分析
func executeGitLabConfigAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	configType, ok := args["config_type"].(string)
	if !ok || configType == "" {
		return GitLabMCPResult{Error: "config_type参数缺失或类型错误"}
	}

	filePattern, _ := args["file_pattern"].(string)

	// 定义配置文件模式
	configPatterns := map[string][]string{
		"security": {
			"security", "auth", "permission", "access", "cors",
			"ssl", "tls", "certificate", "encryption",
		},
		"database": {
			"database", "db", "connection", "url", "host",
			"port", "username", "password", "schema",
		},
		"network": {
			"network", "host", "port", "url", "endpoint",
			"proxy", "firewall", "cors", "origin",
		},
		"application": {
			"application", "app", "server", "port", "host",
			"debug", "log", "level", "environment",
		},
	}

	patterns, exists := configPatterns[configType]
	if !exists {
		// 如果没有预定义模式，使用配置类型作为关键词
		patterns = []string{configType}
	}

	// 搜索配置文件
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

		// 检查文件模式过滤
		if filePattern != "" {
			matched := false
			patterns := strings.Split(filePattern, ",")
			for _, pattern := range patterns {
				pattern = strings.TrimSpace(pattern)
				if strings.Contains(item.Path, pattern) || strings.HasSuffix(item.Path, pattern) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
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

		// 在文件内容中搜索配置模式
		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					searchResults = append(searchResults, map[string]interface{}{
						"file_path":   item.Path,
						"line_number": lineNum + 1,
						"pattern":     pattern,
						"context":     getLineContext(lines, lineNum, 2),
						"type":        "config",
					})
				}
			}
		}
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"config_type":  configType,
		"file_pattern": filePattern,
		"results":      searchResults,
		"total_results": len(searchResults),
	})

	return GitLabMCPResult{Content: string(resultJSON)}
}

// FunctionCallInfo 函数调用信息
type FunctionCallInfo struct {
	FunctionName string `json:"function_name"`
	FilePath     string `json:"file_path"`
	LineNumber   int    `json:"line_number"`
	Context      string `json:"context"`
	Depth        int    `json:"depth"`
	IsDefinition bool   `json:"is_definition"`
}

// RecursiveAnalysisResult 递归分析结果
type RecursiveAnalysisResult struct {
	StartFunction    string              `json:"start_function"`
	StartFilePath    string              `json:"start_file_path"`
	CallChain        []FunctionCallInfo  `json:"call_chain"`
	SecurityIssues   []map[string]interface{} `json:"security_issues"`
	MaxDepth         int                 `json:"max_depth"`
	TotalFunctions   int                 `json:"total_functions"`
	CrossFileCalls   int                 `json:"cross_file_calls"`
}

// executeGitLabRecursiveFunctionAnalysis 执行递归函数调用分析
func executeGitLabRecursiveFunctionAnalysis(args map[string]interface{}, git *gitlab.Client, projectID int) GitLabMCPResult {
	filePath, ok := GetStringParam(args, "file_path", "filePath", "filepath")
	if !ok {
		return GitLabMCPResult{Error: "file_path/filePath/filepath参数缺失或类型错误"}
	}

	functionName, ok := GetStringParam(args, "function_name", "functionName", "function")
	if !ok {
		return GitLabMCPResult{Error: "function_name/functionName/function参数缺失或类型错误"}
	}

	maxDepth := 3 // 默认最大深度
	if depth, ok := args["max_depth"].(float64); ok {
		maxDepth = int(depth)
	}

	includeSecurityAnalysis := true
	if security, ok := args["include_security_analysis"].(bool); ok {
		includeSecurityAnalysis = security
	}

	analyzeCrossFileCalls := true
	if crossFile, ok := args["analyze_cross_file_calls"].(bool); ok {
		analyzeCrossFileCalls = crossFile
	}

	// 初始化结果
	result := &RecursiveAnalysisResult{
		StartFunction:  functionName,
		StartFilePath:  filePath,
		MaxDepth:       maxDepth,
		CallChain:      []FunctionCallInfo{},
		SecurityIssues: []map[string]interface{}{},
	}

	// 开始递归分析
	analyzedFunctions := make(map[string]bool) // 防止循环调用
	analyzeFunctionRecursively(git, projectID, functionName, filePath, 0, maxDepth, result, analyzedFunctions, includeSecurityAnalysis, analyzeCrossFileCalls)

	resultJSON, _ := json.Marshal(result)
	return GitLabMCPResult{Content: string(resultJSON)}
}

// analyzeFunctionRecursively 递归分析函数
func analyzeFunctionRecursively(git *gitlab.Client, projectID int, functionName, filePath string, currentDepth, maxDepth int, result *RecursiveAnalysisResult, analyzedFunctions map[string]bool, includeSecurityAnalysis, analyzeCrossFileCalls bool) {
	// 防止无限递归
	if currentDepth >= maxDepth {
		return
	}

	// 创建函数标识符
	functionKey := fmt.Sprintf("%s:%s", filePath, functionName)
	if analyzedFunctions[functionKey] {
		return // 已经分析过，避免循环
	}
	analyzedFunctions[functionKey] = true

	// 获取文件内容
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: gitlab.String("main"),
	})
	if err != nil {
		return
	}

	// 解码Base64内容
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	
	// 查找函数定义
	var functionStart, functionEnd int
	var functionContent string
	
	for i, line := range lines {
		if strings.Contains(line, "func "+functionName) || strings.Contains(line, "func("+functionName) {
			functionStart = i + 1
			functionEnd = findFunctionEnd(lines, i)
			functionContent = strings.Join(lines[functionStart-1:functionEnd], "\n")
			break
		}
	}

	if functionContent == "" {
		return // 函数未找到
	}

	// 添加到调用链
	callInfo := FunctionCallInfo{
		FunctionName: functionName,
		FilePath:     filePath,
		LineNumber:   functionStart,
		Context:      getLineContext(lines, functionStart-1, 3),
		Depth:        currentDepth,
		IsDefinition: true,
	}
	result.CallChain = append(result.CallChain, callInfo)
	result.TotalFunctions++

	// 安全分析
	if includeSecurityAnalysis {
		securityIssues := analyzeFunctionSecurity(functionContent, functionName, filePath, functionStart)
		for _, issue := range securityIssues {
			issue["depth"] = currentDepth
			issue["function_name"] = functionName
			result.SecurityIssues = append(result.SecurityIssues, issue)
		}
	}

	// 查找函数调用
	calledFunctions := extractFunctionCalls(functionContent, functionName)
	
	for _, calledFunc := range calledFunctions {
		// 递归分析被调用的函数
		if analyzeCrossFileCalls {
			// 尝试在不同文件中查找函数定义
			calledFuncPath := findFunctionDefinition(git, projectID, calledFunc, filePath)
			if calledFuncPath != "" {
				result.CrossFileCalls++
				analyzeFunctionRecursively(git, projectID, calledFunc, calledFuncPath, currentDepth+1, maxDepth, result, analyzedFunctions, includeSecurityAnalysis, analyzeCrossFileCalls)
			} else {
				// 在当前文件中查找
				analyzeFunctionRecursively(git, projectID, calledFunc, filePath, currentDepth+1, maxDepth, result, analyzedFunctions, includeSecurityAnalysis, analyzeCrossFileCalls)
			}
		} else {
			// 只在当前文件中查找
			analyzeFunctionRecursively(git, projectID, calledFunc, filePath, currentDepth+1, maxDepth, result, analyzedFunctions, includeSecurityAnalysis, analyzeCrossFileCalls)
		}
	}
}

// extractFunctionCalls 从函数内容中提取函数调用
func extractFunctionCalls(functionContent, currentFunction string) []string {
	var calledFunctions []string
	lines := strings.Split(functionContent, "\n")
	
	// 简单的函数调用模式匹配
	// callPatterns := []string{
	// 	`(\w+)\(`,           // 基本函数调用
	// 	`(\w+)\.(\w+)\(`,    // 方法调用
	// 	`(\w+)\[`,           // 数组访问
	// 	`(\w+)\.(\w+)`,      // 属性访问
	// }
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}
		
		// 简单的函数调用检测
		// 这里使用简单的字符串匹配，实际项目中可以使用正则表达式
		if strings.Contains(line, "(") && !strings.Contains(line, "func ") {
			// 提取可能的函数名
			parts := strings.Split(line, "(")
			if len(parts) > 0 {
				funcPart := strings.TrimSpace(parts[0])
				// 提取最后一个部分作为函数名
				funcParts := strings.Split(funcPart, ".")
				if len(funcParts) > 0 {
					funcName := strings.TrimSpace(funcParts[len(funcParts)-1])
					if funcName != "" && funcName != currentFunction && !contains(calledFunctions, funcName) {
						calledFunctions = append(calledFunctions, funcName)
					}
				}
			}
		}
	}
	
	return calledFunctions
}

// findFunctionDefinition 在项目中查找函数定义
func findFunctionDefinition(git *gitlab.Client, projectID int, functionName, currentFilePath string) string {
	// 获取项目文件列表
	tree, _, err := git.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
		Recursive: gitlab.Bool(true),
		Ref:       gitlab.String("main"),
	})
	if err != nil {
		return ""
	}

	// 优先搜索同目录下的文件
	currentDir := getDirectoryFromPath(currentFilePath)
	
	for _, item := range tree {
		if item.Type == "tree" {
			continue
		}
		
		// 优先检查同目录下的文件
		if getDirectoryFromPath(item.Path) == currentDir {
			if hasFunctionDefinition(git, projectID, item.Path, functionName) {
				return item.Path
			}
		}
	}
	
	// 然后搜索其他文件
	for _, item := range tree {
		if item.Type == "tree" {
			continue
		}
		
		if getDirectoryFromPath(item.Path) != currentDir {
			if hasFunctionDefinition(git, projectID, item.Path, functionName) {
				return item.Path
			}
		}
	}
	
	return ""
}

// hasFunctionDefinition 检查文件中是否包含函数定义
func hasFunctionDefinition(git *gitlab.Client, projectID int, filePath, functionName string) bool {
	file, _, err := git.RepositoryFiles.GetFile(projectID, filePath, &gitlab.GetFileOptions{
		Ref: gitlab.String("main"),
	})
	if err != nil {
		return false
	}

	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return false
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "func "+functionName) || strings.Contains(line, "func("+functionName) {
			return true
		}
	}
	
	return false
}

// analyzeFunctionSecurity 分析函数的安全性
func analyzeFunctionSecurity(functionContent, functionName, filePath string, startLine int) []map[string]interface{} {
	var issues []map[string]interface{}
	lines := strings.Split(functionContent, "\n")
	
	// 安全模式检测
	securityPatterns := map[string][]string{
		"sql_injection": {"SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "UNION", "query(", "exec("},
		"command_injection": {"exec(", "system(", "shell_exec(", "passthru(", "os.Exec", "subprocess"},
		"xss": {"innerHTML", "outerHTML", "document.write", "eval(", "<script>", "javascript:"},
		"path_traversal": {"../", "..\\", "~", "/etc/", "C:\\", "file://"},
		"ssrf": {"http.Get", "http.Post", "fetch(", "axios.get", "urllib.request"},
		"auth_bypass": {"admin", "root", "password", "token", "secret", "bypass", "skip"},
	}
	
	for lineNum, line := range lines {
		line = strings.ToLower(line)
		for issueType, patterns := range securityPatterns {
			for _, pattern := range patterns {
				if strings.Contains(line, strings.ToLower(pattern)) {
					issues = append(issues, map[string]interface{}{
						"type":        issueType,
						"pattern":     pattern,
						"line_number": startLine + lineNum,
						"file_path":   filePath,
						"function":    functionName,
						"context":     getLineContext(lines, lineNum, 2),
						"severity":    determineSeverity(pattern, issueType),
					})
				}
			}
		}
	}
	
	return issues
}

// getDirectoryFromPath 从文件路径中提取目录
func getDirectoryFromPath(filePath string) string {
	lastSlash := strings.LastIndex(filePath, "/")
	if lastSlash == -1 {
		return ""
	}
	return filePath[:lastSlash]
}

// contains 检查切片是否包含元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
} 