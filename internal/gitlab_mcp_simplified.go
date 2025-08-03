package internal

import (
	"fmt"

	"github.com/xanzy/go-gitlab"
)

// SimplifiedGitLabMCPTools 纯通用MCP工具，让模型自由发挥
var SimplifiedGitLabMCPTools = []GitLabMCPTool{
	{
		Name:        "gitlab_file_content",
		Description: "获取GitLab仓库中指定文件的完整内容，用于分析代码逻辑、函数定义、变量声明等",
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
		Description: "获取GitLab仓库中指定文件的基本信息（行数、大小、类型等），用于了解文件结构",
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
		Description: "在GitLab仓库中搜索指定的文本或模式，用于查找相关代码、函数调用、变量使用等",
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
		Description: "分析代码片段的上下文关系，包括前后代码、函数调用、数据流等，用于理解代码逻辑",
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
		Description: "分析特定函数的完整定义、调用关系、参数传递等，用于深入理解函数逻辑",
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
		Description: "递归分析函数调用链，追踪函数间的调用关系，深入分析被调用函数的实现",
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
				"analyze_cross_file_calls": map[string]interface{}{
					"type":        "boolean",
					"description": "是否分析跨文件调用（可选，默认true）",
				},
			},
			"required": []string{"file_path", "function_name"},
		},
	},
	{
		Name:        "gitlab_dependency_analysis",
		Description: "分析项目依赖的基本信息，包括版本、依赖关系等",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"file_path": map[string]interface{}{
					"type":        "string",
					"description": "依赖文件路径（如go.mod、package.json、requirements.txt等）",
				},
			},
			"required": []string{"file_path"},
		},
	},
}

// SimplifiedGitLabMCPExecutor 简化版MCP执行器
func SimplifiedGitLabMCPExecutor(call GitLabMCPCall, git *gitlab.Client, projectID int) GitLabMCPResult {
	switch call.ToolName {
	case "gitlab_file_content":
		return executeGitLabFileContent(call.Arguments, git, projectID)
	case "gitlab_file_info":
		return executeGitLabFileInfo(call.Arguments, git, projectID)
	case "gitlab_search_code":
		return executeGitLabSearchCode(call.Arguments, git, projectID)
	case "gitlab_context_analysis":
		return executeGitLabContextAnalysis(call.Arguments, git, projectID)
	case "gitlab_function_analysis":
		return executeGitLabFunctionAnalysis(call.Arguments, git, projectID)
	case "gitlab_recursive_function_analysis":
		return executeGitLabRecursiveFunctionAnalysis(call.Arguments, git, projectID)
	case "gitlab_dependency_analysis":
		return executeGitLabDependencyAnalysis(call.Arguments, git, projectID)
	default:
		return GitLabMCPResult{Error: fmt.Sprintf("未知的工具: %s", call.ToolName)}
	}
}

// GetAvailableSimplifiedGitLabTools 获取可用的简化版GitLab工具
func GetAvailableSimplifiedGitLabTools() []GitLabMCPTool {
	return SimplifiedGitLabMCPTools
} 