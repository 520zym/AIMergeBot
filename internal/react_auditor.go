package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/sashabaranov/go-openai"
	"github.com/xanzy/go-gitlab"
)

// ReActStep 定义ReAct推理步骤
type ReActStep struct {
	Thought    string     `json:"thought"`
	Action     string     `json:"action"`
	ActionArgs map[string]interface{} `json:"action_args,omitempty"`
	Observation string    `json:"observation"`
	ToolResults []map[string]interface{} `json:"tool_results,omitempty"` // 保存工具调用的具体结果
}

// ReActAuditResult 定义ReAct审计结果
type ReActAuditResult struct {
	Steps      []ReActStep    `json:"steps"`
	FinalAnswer string        `json:"final_answer"`
	Issues     []SecurityIssue `json:"issues"`
	Recommendations []string  `json:"recommendations,omitempty"`
	RiskLevel  string         `json:"risk_level,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// ReActAuditor ReAct代码审计器
type ReActAuditor struct {
	client    *openai.Client
	model     string
	repoPath  string
	maxSteps  int
	gitClient *gitlab.Client
	projectID int
	mcpMode   string // 新增MCP模式字段
	// 新增配置参数
	temperature float64
	maxRetries  int
	verbose     bool
}

// NewReActAuditor 创建新的ReAct审计器
func NewReActAuditor(apiKey, baseURL, model, repoPath string) *ReActAuditor {
	var client *openai.Client
	if baseURL != "" {
		cfg := openai.DefaultConfig(apiKey)
		cfg.BaseURL = baseURL
		client = openai.NewClientWithConfig(cfg)
	} else {
		client = openai.NewClient(apiKey)
	}
	
	if model == "" {
		model = "gpt-4o-mini" // 使用更通用的默认模型
	}

	return &ReActAuditor{
		client:      client,
		model:       model,
		repoPath:    repoPath,
		maxSteps:    10, // 默认最大推理步骤数
		temperature: 0.1, // 默认温度参数
		maxRetries:  3,   // 默认最大重试次数
		verbose:     false, // 默认不启用详细日志
	}
}

// NewReActAuditorWithGitLab 创建支持GitLab API的ReAct审计器
func NewReActAuditorWithGitLab(apiKey, baseURL, model string, gitClient *gitlab.Client, projectID int, mcpMode string) *ReActAuditor {
	var client *openai.Client
	if baseURL != "" {
		cfg := openai.DefaultConfig(apiKey)
		cfg.BaseURL = baseURL
		client = openai.NewClientWithConfig(cfg)
	} else {
		client = openai.NewClient(apiKey)
	}
	
	if model == "" {
		model = "gpt-4o-mini" // 使用更通用的默认模型
	}

	return &ReActAuditor{
		client:      client,
		model:       model,
		repoPath:    "",
		maxSteps:    10, // 默认最大推理步骤数
		gitClient:   gitClient,
		projectID:   projectID,
		mcpMode:     mcpMode,
		temperature: 0.1, // 默认温度参数
		maxRetries:  3,   // 默认最大重试次数
		verbose:     false, // 默认不启用详细日志
	}
}

// NewReActAuditorWithConfig 创建支持配置的ReAct审计器
func NewReActAuditorWithConfig(apiKey, baseURL, model string, gitClient *gitlab.Client, projectID int, mcpMode string, maxSteps int, temperature float64, maxRetries int, verbose bool) *ReActAuditor {
	var client *openai.Client
	if baseURL != "" {
		cfg := openai.DefaultConfig(apiKey)
		cfg.BaseURL = baseURL
		client = openai.NewClientWithConfig(cfg)
	} else {
		client = openai.NewClient(apiKey)
	}
	
	if model == "" {
		model = "gpt-4o-mini" // 使用更通用的默认模型
	}

	// 设置默认值
	if maxSteps <= 0 {
		maxSteps = 10
	}
	if temperature <= 0 {
		temperature = 0.1
	}
	if maxRetries <= 0 {
		maxRetries = 3
	}

	return &ReActAuditor{
		client:      client,
		model:       model,
		repoPath:    "",
		maxSteps:    maxSteps,
		gitClient:   gitClient,
		projectID:   projectID,
		mcpMode:     mcpMode,
		temperature: temperature,
		maxRetries:  maxRetries,
		verbose:     verbose,
	}
}

// AuditWithReAct 使用ReAct方法进行代码审计
func (r *ReActAuditor) AuditWithReAct(diff string, projectInfo map[string]interface{}) (*ReActAuditResult, error) {
	result := &ReActAuditResult{
		Steps: make([]ReActStep, 0),
	}

	// 添加MCP模式日志
	log.Printf("=== ReAct审计开始 ===")
	log.Printf("MCP模式: %s", r.mcpMode)
	if r.mcpMode == "simplified" {
		log.Printf("使用简化版MCP工具集（7个通用工具）")
	} else if r.mcpMode == "full" {
		log.Printf("使用完整版MCP工具集（16个工具，包含安全工具）")
	}
	log.Printf("最大推理步骤: %d", r.maxSteps)
	log.Printf("模型: %s", r.model)
	log.Printf("温度参数: %.2f", r.temperature)
	log.Printf("最大重试次数: %d", r.maxRetries)
	log.Printf("详细日志: %t", r.verbose)
	log.Printf("=====================")

	// 构建初始提示
	systemPrompt := r.buildSystemPrompt()
	userPrompt := r.buildInitialPrompt(diff, projectInfo)

	messages := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
		{Role: openai.ChatMessageRoleUser, Content: userPrompt},
	}

	// 开始ReAct推理循环
	for step := 0; step < r.maxSteps; step++ {
		log.Printf("ReAct步骤 %d - 开始推理", step+1)

		// 调用大模型进行思考（带重试机制）
		log.Printf("ReAct步骤 %d - 调用大模型: %s", step+1, r.model)
		
		var resp openai.ChatCompletionResponse
		var err error
		
		for retry := 0; retry < r.maxRetries; retry++ {
			if retry > 0 {
				log.Printf("ReAct步骤 %d - 重试第 %d 次", step+1, retry)
				time.Sleep(time.Duration(retry) * time.Second) // 递增延迟
			}
			
			resp, err = r.client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
				Model:    r.model,
				Messages: messages,
				Temperature: float32(r.temperature), // 使用配置的温度参数
			})
			
			if err == nil {
				break // 成功，跳出重试循环
			}
			
			log.Printf("ReAct步骤 %d - 大模型调用失败 (重试 %d/%d): %v", step+1, retry+1, r.maxRetries, err)
			
			// 如果是限流错误，继续重试
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "rate limit") {
				continue
			}
			
			// 其他错误，直接返回
			break
		}
		
		if err != nil {
			log.Printf("ReAct步骤 %d - 大模型调用最终失败: %v", step+1, err)
			result.Error = fmt.Sprintf("调用大模型失败: %v", err)
			return result, err
		}

		if len(resp.Choices) == 0 {
			log.Printf("ReAct步骤 %d - 大模型未返回有效响应", step+1)
			result.Error = "大模型未返回有效响应"
			return result, fmt.Errorf("大模型未返回有效响应")
		}

		content := resp.Choices[0].Message.Content
		log.Printf("ReAct步骤 %d - 大模型响应长度: %d", step+1, len(content))
		
		// 解析ReAct格式的响应
		reactStep, isFinal, err := r.parseReActResponse(content)
		if err != nil {
			log.Printf("ReAct步骤 %d - 解析响应失败: %v", step+1, err)
			result.Error = fmt.Sprintf("解析ReAct响应失败: %v", err)
			return result, err
		}

		log.Printf("ReAct步骤 %d - 思考: %s", step+1, reactStep.Thought)
		if reactStep.Action != "" {
			log.Printf("ReAct步骤 %d - 工具调用: %s", step+1, reactStep.Action)
		}

		// 如果是最终答案，结束推理
		if isFinal {
			log.Printf("ReAct步骤 %d - 到达最终答案", step+1)
			result.FinalAnswer = reactStep.Thought
			
			// 尝试解析最终分析的JSON格式
			finalAnalysis, err := r.parseFinalAnalysis(content)
			if err != nil {
				log.Printf("ReAct步骤 %d - 解析最终分析JSON失败: %v", step+1, err)
				// 如果JSON解析失败，回退到原来的关键词匹配方法
				issues := r.extractSecurityIssues(result.FinalAnswer, diff)
				result.Issues = issues
				// 添加默认建议
				result.Recommendations = []string{
					"建议进行全面的安全代码审查",
					"建议使用静态代码分析工具",
					"建议定期进行安全培训",
				}
				result.RiskLevel = "medium" // 默认中等风险
				log.Printf("ReAct分析完成 - 使用关键词匹配提取到 %d 个安全问题", len(issues))
			} else {
				log.Printf("ReAct步骤 %d - 成功解析最终分析JSON", step+1)
				// 将JSON格式的问题转换为SecurityIssue格式
				issues, recommendations, riskLevel := r.convertIssuesFromJSON(finalAnalysis, diff)
				result.Issues = issues
				result.Recommendations = recommendations
				result.RiskLevel = riskLevel
				log.Printf("ReAct分析完成 - 从JSON提取到 %d 个安全问题, %d 个建议", len(issues), len(recommendations))
			}
			break
		}

		// 执行工具调用
		if reactStep.Action != "" {
			log.Printf("ReAct步骤 %d - 执行工具: %s", step+1, reactStep.Action)
			observation := r.executeTool(reactStep.Action, reactStep.ActionArgs)
			reactStep.Observation = observation
			log.Printf("ReAct步骤 %d - 工具执行结果长度: %d", step+1, len(observation))
			
			// 保存详细的工具调用结果
			toolResult := map[string]interface{}{
				"tool_name":    reactStep.Action,
				"tool_args":    reactStep.ActionArgs,
				"raw_output":   observation,
				"output_length": len(observation),
			}
			
			// 尝试解析JSON输出以提供结构化结果
			var parsedOutput interface{}
			if err := json.Unmarshal([]byte(observation), &parsedOutput); err == nil {
				toolResult["parsed_output"] = parsedOutput
			}
			
			reactStep.ToolResults = append(reactStep.ToolResults, toolResult)
			
			// 更新消息历史
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleAssistant,
				Content: content,
			})
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleUser,
				Content: fmt.Sprintf("Observation: %s\n\n继续分析，如果需要更多信息请继续调用工具，如果分析完成请给出最终答案。", observation),
			})
		}
		
		// 将步骤添加到结果中
		result.Steps = append(result.Steps, *reactStep)
	}

	return result, nil
}

// buildSystemPrompt 构建系统提示词
func (r *ReActAuditor) buildSystemPrompt() string {
	switch r.mcpMode {
	case "simplified":
		return r.buildSimplifiedPrompt()
	case "full":
		return r.buildFullPrompt()
	default:
		return r.buildSimplifiedPrompt() // 默认使用简化模式
	}
}

// buildSimplifiedPrompt 构建简化模式的提示词
func (r *ReActAuditor) buildSimplifiedPrompt() string {
	return `你是一个专业的代码安全审计专家，使用ReAct方法进行深度代码分析。

## 核心原则
1. **必须使用工具进行深入分析**，不能仅基于MR diff就得出结论
2. **自主发现安全问题**，基于代码逻辑而非预设模式
3. **多步骤推理**，通过工具调用深入理解代码逻辑
4. **上下文验证**，结合完整上下文判断风险真实性

## 可用工具

### 基础工具
1. **gitlab_project_structure** - 获取项目结构
   - 用途：了解项目组织架构
   - 参数：ref, include_content, file_type_filter

2. **gitlab_global_search** - 全局搜索
   - 用途：跨文件搜索特定模式
   - 参数：search_patterns[], file_patterns[], exclude_patterns[], case_sensitive, include_context, context_lines

3. **gitlab_file_content** - 获取文件完整内容
   - 参数：file_path, ref

4. **gitlab_file_info** - 获取文件基本信息
   - 参数：file_path, ref

5. **gitlab_search_code** - 搜索代码中的特定模式
   - 参数：query, file_type

6. **gitlab_context_analysis** - 分析代码上下文
   - 参数：file_path, line_number, context_lines

7. **gitlab_function_analysis** - 分析函数定义和调用
   - 参数：file_path, function_name, include_calls

8. **gitlab_recursive_function_analysis** - 递归分析函数调用链
   - 参数：file_path, function_name, max_depth, analyze_cross_file_calls

9. **gitlab_dependency_analysis** - 分析项目依赖
   - 参数：file_path

## 强制分析流程

### 第一阶段：基础信息收集（必须执行）
1. 使用 gitlab_file_info 了解变更文件基本信息
2. 使用 gitlab_file_content 获取变更文件完整内容
3. 使用 gitlab_context_analysis 分析关键代码段上下文

### 第二阶段：深度安全审计（必须执行）
1. **输入验证审计**
   - 使用 gitlab_search_code 搜索用户输入处理
   - 使用 gitlab_function_analysis 分析输入验证函数

2. **认证授权审计**
   - 使用 gitlab_search_code 搜索认证相关代码
   - 使用 gitlab_recursive_function_analysis 追踪认证调用链

3. **敏感信息审计**
   - 使用 gitlab_search_code 搜索硬编码敏感信息
   - 使用 gitlab_context_analysis 分析敏感数据处理

4. **文件操作审计**
   - 使用 gitlab_search_code 搜索文件操作代码
   - 使用 gitlab_function_analysis 分析文件操作函数

5. **网络通信审计**
   - 使用 gitlab_search_code 搜索网络请求代码
   - 使用 gitlab_function_analysis 分析网络操作函数

6. **业务逻辑审计**
   - 使用 gitlab_search_code 搜索业务逻辑代码
   - 使用 gitlab_recursive_function_analysis 追踪业务逻辑调用链

7. **依赖安全审计**
   - 使用 gitlab_dependency_analysis 检查依赖安全

8. **错误处理审计**
   - 使用 gitlab_search_code 搜索错误处理代码
   - 使用 gitlab_context_analysis 分析错误信息泄露

## 智能搜索策略

### 关键搜索模式
- **用户输入**：input, user_input, request, params, query, form, body
- **数据库操作**：SELECT, INSERT, UPDATE, DELETE, WHERE, UNION, query, exec
- **文件操作**：file, path, read, write, upload, download, open, create
- **网络请求**：http, url, fetch, request, api, curl, wget
- **命令执行**：exec, system, shell, command, os, subprocess
- **认证相关**：auth, login, password, token, session, cookie
- **加密解密**：encrypt, decrypt, hash, md5, sha, bcrypt
- **错误处理**：error, exception, catch, try, log, debug

### 上下文长度策略
- **快速定位**：context_lines=5
- **函数分析**：context_lines=10
- **深度分析**：context_lines=15-20
- **安全审计**：context_lines=20-30

## 响应格式

### 每个推理步骤
{
  "thought": "思考过程和分析",
  "action": "工具名称（如不需要则为空）",
  "action_args": {
    "参数名": "参数值"
  }
}

### 最终分析结果
{
  "thought": "最终分析总结",
  "action": "",
  "final_analysis": {
    "summary": "整体安全评估总结",
    "issues": [
      {
        "type": "安全问题类型",
        "description": "问题详细描述",
        "severity": "high/medium/low",
        "location": "问题位置",
        "suggestion": "修复建议"
      }
    ],
    "risk_level": "high/medium/low",
    "recommendations": [
      "具体修复建议1",
      "具体修复建议2"
    ]
  }
}

## 误报控制策略
1. **多重验证**：对每个潜在风险进行多角度验证
2. **上下文确认**：确保理解完整的业务逻辑
3. **安全机制检查**：搜索相关的安全防护措施
4. **业务场景理解**：结合业务场景判断是否为真实漏洞
5. **风险等级评估**：根据利用难度和影响范围评估风险等级

## 重要提醒
- 每个响应必须是有效的JSON格式
- 必须严格按照指定的字段名称和结构
- 如果不需要调用工具，action字段必须为空字符串
- 最终分析必须包含final_analysis字段

记住：你的目标是提供准确、全面、可操作的安全分析结果，让模型基于通用工具自主发现安全问题。`
}

// buildFullPrompt 构建完整模式的提示词
func (r *ReActAuditor) buildFullPrompt() string {
	return `你是一个专业的代码安全审计专家，使用ReAct方法进行深度代码安全分析。

## 核心原则
1. **必须使用工具进行深入分析**，不能仅基于MR diff就得出结论
2. **结合预定义模式和深度推理**，提供全面的安全分析
3. **多步骤推理**，通过工具调用深入理解代码逻辑
4. **上下文验证**，结合完整上下文判断风险真实性

## 可用工具

### 基础工具
1. **gitlab_project_structure** - 获取项目结构
2. **gitlab_global_search** - 全局搜索
3. **gitlab_file_content** - 获取文件完整内容
4. **gitlab_file_info** - 获取文件基本信息
5. **gitlab_search_code** - 搜索代码中的特定模式
6. **gitlab_context_analysis** - 分析代码上下文
7. **gitlab_function_analysis** - 分析函数定义和调用
8. **gitlab_recursive_function_analysis** - 递归分析函数调用链
9. **gitlab_dependency_analysis** - 分析项目依赖

### 安全分析工具
10. **gitlab_security_pattern_search** - 搜索特定安全漏洞模式
11. **gitlab_authentication_analysis** - 分析认证和授权机制
12. **gitlab_input_validation_analysis** - 分析输入验证机制
13. **gitlab_network_operation_analysis** - 分析网络操作安全性
14. **gitlab_data_flow_analysis** - 追踪数据流
15. **gitlab_api_endpoint_analysis** - 分析API端点安全
16. **gitlab_error_handling_analysis** - 分析错误处理机制
17. **gitlab_file_operation_analysis** - 分析文件操作安全
18. **gitlab_config_analysis** - 分析配置文件安全

## 分层安全分析策略

### 第一层：基础信息收集（必须执行）
1. 使用 gitlab_file_info 了解文件结构
2. 使用 gitlab_file_content 获取完整内容

### 第二层：模式识别（必须执行）
1. 使用 gitlab_security_pattern_search 搜索漏洞模式
2. 使用 gitlab_search_code 搜索特定代码

### 第三层：深度分析（必须执行）
1. 使用 gitlab_function_analysis 分析关键函数
2. 使用 gitlab_context_analysis 分析代码上下文

### 第四层：专项审计（必须执行）
1. 使用 gitlab_dependency_analysis 依赖安全检查
2. 使用 gitlab_config_analysis 配置安全审查
3. 使用 gitlab_api_endpoint_analysis API安全审计

### 第五层：风险追踪（必须执行）
1. 使用 gitlab_data_flow_analysis 数据流追踪
2. 使用 gitlab_error_handling_analysis 错误处理检查
3. 使用 gitlab_authentication_analysis 认证机制分析

## 安全分析重点

### 1. 注入漏洞分析
- **SQL注入**：使用 gitlab_security_pattern_search 搜索SQL相关模式
- **XSS攻击**：使用 gitlab_security_pattern_search 搜索XSS相关模式
- **命令注入**：使用 gitlab_security_pattern_search 搜索命令执行模式

### 2. 认证授权分析
- **认证绕过**：使用 gitlab_authentication_analysis 分析认证机制
- **权限提升**：使用 gitlab_authentication_analysis 分析权限控制

### 3. 数据安全分析
- **数据泄露**：使用 gitlab_data_flow_analysis 追踪敏感数据流
- **配置安全**：使用 gitlab_config_analysis 检查配置问题

### 4. 网络安全分析
- **SSRF漏洞**：使用 gitlab_network_operation_analysis 分析网络请求
- **API安全**：使用 gitlab_api_endpoint_analysis 审计API端点

### 5. 文件操作安全
- **路径遍历**：使用 gitlab_file_operation_analysis 分析文件操作
- **上传下载**：使用 gitlab_file_operation_analysis 检查文件处理

### 6. 错误处理安全
- **信息泄露**：使用 gitlab_error_handling_analysis 检查错误处理
- **调试信息**：使用 gitlab_error_handling_analysis 分析调试输出

## 智能工具调用策略

### 上下文长度智能配置
- **快速定位**：context_lines=5
- **函数分析**：context_lines=10
- **深度分析**：context_lines=15-20
- **安全审计**：context_lines=20-30

### 分析深度策略
- **第一层**：使用 gitlab_file_info 了解文件结构
- **第二层**：使用 gitlab_security_pattern_search 快速定位风险点
- **第三层**：使用 gitlab_context_analysis 深入分析风险点上下文
- **第四层**：使用 gitlab_function_analysis 分析相关函数
- **第五层**：使用 gitlab_search_code 搜索相关代码模式

## 响应格式

### 每个推理步骤
{
  "thought": "思考过程和分析",
  "action": "工具名称（如不需要则为空）",
  "action_args": {
    "参数名": "参数值"
  }
}

### 最终分析结果
{
  "thought": "最终分析总结",
  "action": "",
  "final_analysis": {
    "summary": "整体安全评估总结",
    "issues": [
      {
        "type": "安全问题类型",
        "description": "问题详细描述",
        "severity": "high/medium/low",
        "location": "问题位置",
        "suggestion": "修复建议"
      }
    ],
    "risk_level": "high/medium/low",
    "recommendations": [
      "具体修复建议1",
      "具体修复建议2"
    ]
  }
}

## 误报控制策略
1. **多重验证**：对每个潜在漏洞进行多角度验证
2. **上下文确认**：确保理解完整的业务逻辑和认证机制
3. **安全机制检查**：搜索相关的安全防护措施
4. **业务场景理解**：结合业务场景判断是否为真实漏洞
5. **风险等级评估**：根据利用难度和影响范围评估风险等级

## 重要提醒
- 每个响应必须是有效的JSON格式
- 必须严格按照指定的字段名称和结构
- 如果不需要调用工具，action字段必须为空字符串
- 最终分析必须包含final_analysis字段

记住：你的目标是提供准确、全面、可操作的安全分析结果，结合预定义模式和深度推理进行安全分析。`
}

// buildInitialPrompt 构建初始用户提示
func (r *ReActAuditor) buildInitialPrompt(diff string, projectInfo map[string]interface{}) string {
	return fmt.Sprintf(`请对以下代码变更进行全面的白盒安全审计：

## 项目信息：
- 项目ID: %v
- 项目名称: %v
- 分支: %v

## 代码变更：
%s

## 重要提醒：
**你必须使用MCP工具进行深入分析，不能仅基于MR diff就得出结论！**

## 强制审计流程：

### 第一阶段：必须执行的基础信息收集
**每个分析都必须包含以下步骤：**
1. 使用 gitlab_file_info 了解变更文件的基本信息
2. 使用 gitlab_file_content 获取变更文件的完整内容
3. 使用 gitlab_context_analysis 分析代码上下文

### 第二阶段：必须执行的深度安全审计
**必须使用以下工具进行深入分析：**

1. **输入验证审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索用户输入处理代码
   - 使用 gitlab_function_analysis 分析输入验证函数
   - 使用 gitlab_context_analysis 分析输入处理上下文

2. **认证授权审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索认证相关代码
   - 使用 gitlab_function_analysis 分析认证函数
   - 使用 gitlab_recursive_function_analysis 追踪认证调用链

3. **敏感信息审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索硬编码敏感信息
   - 使用 gitlab_search_code 搜索加密相关代码
   - 使用 gitlab_context_analysis 分析敏感数据处理

4. **文件操作审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索文件操作代码
   - 使用 gitlab_function_analysis 分析文件操作函数
   - 使用 gitlab_context_analysis 分析路径处理逻辑

5. **网络通信审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索网络请求代码
   - 使用 gitlab_function_analysis 分析网络操作函数
   - 使用 gitlab_context_analysis 分析API调用上下文

6. **业务逻辑审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索业务逻辑代码
   - 使用 gitlab_function_analysis 分析关键业务函数
   - 使用 gitlab_recursive_function_analysis 追踪业务逻辑调用链

7. **依赖安全审计**（必须使用工具）
   - 使用 gitlab_dependency_analysis 检查依赖安全
   - 使用 gitlab_search_code 搜索依赖使用情况

8. **错误处理审计**（必须使用工具）
   - 使用 gitlab_search_code 搜索错误处理代码
   - 使用 gitlab_function_analysis 分析错误处理函数
   - 使用 gitlab_context_analysis 分析错误信息泄露

### 第三阶段：必须执行的综合评估
1. 基于工具分析结果评估整体安全风险等级
2. 提供具体的修复建议
3. 推荐安全最佳实践

## 强制使用工具策略：

**每个分析步骤都必须使用以下工具之一：**
1. **gitlab_file_content** - 获取文件完整内容
2. **gitlab_file_info** - 获取文件基本信息
3. **gitlab_search_code** - 搜索代码中的特定模式
4. **gitlab_context_analysis** - 分析代码上下文
5. **gitlab_function_analysis** - 分析函数定义和调用
6. **gitlab_recursive_function_analysis** - 递归分析函数调用链
7. **gitlab_dependency_analysis** - 分析项目依赖

## 分析重点：

- **高危漏洞**：SQL注入、命令注入、路径遍历、SSRF、认证绕过
- **中危漏洞**：XSS、敏感信息泄露、不安全的加密、权限提升
- **低危漏洞**：信息泄露、日志记录不当、配置错误

## 输出要求：

1. **结构化分析**：按安全领域分类问题
2. **风险分级**：明确标注风险等级（high/medium/low）
3. **具体建议**：提供可操作的修复建议
4. **代码示例**：提供安全的代码实现
5. **最佳实践**：推荐相关安全最佳实践

**记住：你必须使用工具进行深入分析，不能仅基于MR diff就得出结论！**

请开始深度安全审计：`, 
		projectInfo["project_id"], 
		projectInfo["project_name"], 
		projectInfo["branch"], 
		diff)
}

// parseReActResponse 解析ReAct格式的响应
func (r *ReActAuditor) parseReActResponse(content string) (*ReActStep, bool, error) {
	// 清理和预处理内容
	content = strings.TrimSpace(content)
	
	// 尝试多种解析策略
	var step ReActStep
	var err error
	
	// 策略1：尝试直接解析完整内容为JSON
	err = json.Unmarshal([]byte(content), &step)
	if err == nil {
		return r.validateAndReturnStep(&step)
	}
	
	// 策略2：尝试提取JSON对象
	jsonStart := strings.Index(content, "{")
	jsonEnd := strings.LastIndex(content, "}")
	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonContent := content[jsonStart:jsonEnd+1]
		err = json.Unmarshal([]byte(jsonContent), &step)
		if err == nil {
			return r.validateAndReturnStep(&step)
		}
	}
	
	// 策略3：尝试提取多个JSON对象，选择最合适的
	jsonObjects := r.extractAllJSONObjects(content)
	for _, jsonObj := range jsonObjects {
		err = json.Unmarshal([]byte(jsonObj), &step)
		if err == nil && r.isValidReActStep(&step) {
			return r.validateAndReturnStep(&step)
		}
	}
	
	// 策略4：尝试解析为map，然后转换为ReActStep
	var responseMap map[string]interface{}
	err = json.Unmarshal([]byte(content), &responseMap)
	if err == nil {
		step = r.convertMapToReActStep(responseMap)
		if r.isValidReActStep(&step) {
			return r.validateAndReturnStep(&step)
		}
	}
	
	// 策略5：尝试提取JSON部分并解析为map
	jsonStart = strings.Index(content, "{")
	jsonEnd = strings.LastIndex(content, "}")
	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonContent := content[jsonStart:jsonEnd+1]
		err = json.Unmarshal([]byte(jsonContent), &responseMap)
		if err == nil {
			step = r.convertMapToReActStep(responseMap)
			if r.isValidReActStep(&step) {
				return r.validateAndReturnStep(&step)
			}
		}
	}
	
	// 策略6：尝试从文本中提取结构化信息
	step = r.extractReActStepFromText(content)
	if r.isValidReActStep(&step) {
		return r.validateAndReturnStep(&step)
	}
	
	// 如果所有策略都失败，返回详细的错误信息
	return nil, false, fmt.Errorf("无法解析ReAct响应，尝试了多种解析策略。响应内容长度: %d, 前100字符: %s", len(content), r.safeSubstring(content, 0, 100))
}

// extractAllJSONObjects 提取内容中的所有JSON对象
func (r *ReActAuditor) extractAllJSONObjects(content string) []string {
	var objects []string
	start := 0
	
	for {
		jsonStart := strings.Index(content[start:], "{")
		if jsonStart == -1 {
			break
		}
		jsonStart += start
		
		// 找到匹配的结束括号
		braceCount := 0
		jsonEnd := -1
		for i := jsonStart; i < len(content); i++ {
			if content[i] == '{' {
				braceCount++
			} else if content[i] == '}' {
				braceCount--
				if braceCount == 0 {
					jsonEnd = i
					break
				}
			}
		}
		
		if jsonEnd > jsonStart {
			jsonContent := content[jsonStart:jsonEnd+1]
			objects = append(objects, jsonContent)
			start = jsonEnd + 1
		} else {
			start = jsonStart + 1
		}
	}
	
	return objects
}

// convertMapToReActStep 将map转换为ReActStep
func (r *ReActAuditor) convertMapToReActStep(responseMap map[string]interface{}) ReActStep {
	step := ReActStep{}
	
	if thought, ok := responseMap["thought"].(string); ok {
		step.Thought = thought
	}
	if action, ok := responseMap["action"].(string); ok {
		step.Action = action
	}
	if actionArgs, ok := responseMap["action_args"].(map[string]interface{}); ok {
		step.ActionArgs = actionArgs
	}
	if observation, ok := responseMap["observation"].(string); ok {
		step.Observation = observation
	}
	if toolResults, ok := responseMap["tool_results"].([]interface{}); ok {
		for _, result := range toolResults {
			if resultMap, ok := result.(map[string]interface{}); ok {
				step.ToolResults = append(step.ToolResults, resultMap)
			}
		}
	}
	
	return step
}

// extractReActStepFromText 从文本中提取ReActStep信息
func (r *ReActAuditor) extractReActStepFromText(content string) ReActStep {
	step := ReActStep{}
	
	// 尝试提取思考内容
	thoughtPatterns := []string{
		`"thought"\s*:\s*"([^"]*)"`,
		`thought\s*:\s*"([^"]*)"`,
		`思考\s*:\s*"([^"]*)"`,
		`思考\s*:\s*([^"]*)`,
	}
	
	for _, pattern := range thoughtPatterns {
		if matches := r.extractWithRegex(content, pattern); len(matches) > 0 {
			step.Thought = matches[0]
			break
		}
	}
	
	// 尝试提取动作
	actionPatterns := []string{
		`"action"\s*:\s*"([^"]*)"`,
		`action\s*:\s*"([^"]*)"`,
		`动作\s*:\s*"([^"]*)"`,
		`动作\s*:\s*([^"]*)`,
	}
	
	for _, pattern := range actionPatterns {
		if matches := r.extractWithRegex(content, pattern); len(matches) > 0 {
			step.Action = matches[0]
			break
		}
	}
	
	// 如果没有找到结构化信息，将整个内容作为思考
	if step.Thought == "" {
		step.Thought = content
	}
	
	return step
}

// extractWithRegex 使用正则表达式提取内容
func (r *ReActAuditor) extractWithRegex(content, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1:]
	}
	return nil
}

// isValidReActStep 验证ReActStep是否有效
func (r *ReActAuditor) isValidReActStep(step *ReActStep) bool {
	// 至少要有思考内容
	return step.Thought != ""
}

// validateAndReturnStep 验证并返回步骤
func (r *ReActAuditor) validateAndReturnStep(step *ReActStep) (*ReActStep, bool, error) {
	// 检查是否为最终答案
	isFinal := strings.Contains(strings.ToLower(step.Thought), "最终答案") || 
			   strings.Contains(strings.ToLower(step.Thought), "final answer") ||
			   strings.Contains(strings.ToLower(step.Thought), "分析完成") ||
			   strings.Contains(strings.ToLower(step.Thought), "analysis complete") ||
			   step.Action == ""

	return step, isFinal, nil
}

// safeSubstring 安全截取字符串
func (r *ReActAuditor) safeSubstring(s string, start, end int) string {
	if start >= len(s) {
		return ""
	}
	if end > len(s) {
		end = len(s)
	}
	if start >= end {
		return ""
	}
	return s[start:end]
}

// FinalAnalysis 定义最终分析结果结构
type FinalAnalysis struct {
	Summary         string   `json:"summary"`
	Issues          []Issue  `json:"issues"`
	RiskLevel       string   `json:"risk_level"`
	Recommendations []string `json:"recommendations"`
	AnalysisProcess string   `json:"analysis_process,omitempty"`
}

// Issue 定义安全问题结构
type Issue struct {
	Type            string `json:"type"`
	Description     string `json:"description"`
	Severity        string `json:"severity"`
	Location        string `json:"location"`
	Suggestion      string `json:"suggestion"`
	Evidence        string `json:"evidence,omitempty"`
	AnalysisContext string `json:"analysis_context,omitempty"`
}

// parseFinalAnalysis 解析最终分析JSON
func (r *ReActAuditor) parseFinalAnalysis(content string) (*FinalAnalysis, error) {
	// 清理和预处理内容
	content = strings.TrimSpace(content)
	
	// 尝试多种解析策略
	var finalAnalysis *FinalAnalysis
	var err error
	
	// 策略1：尝试直接解析完整内容为JSON
	var response map[string]interface{}
	err = json.Unmarshal([]byte(content), &response)
	if err == nil {
		finalAnalysis, err = r.extractFinalAnalysisFromMap(response)
		if err == nil {
			return finalAnalysis, nil
		}
	}
	
	// 策略2：尝试提取JSON对象
	jsonStart := strings.Index(content, "{")
	jsonEnd := strings.LastIndex(content, "}")
	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonContent := content[jsonStart:jsonEnd+1]
		err = json.Unmarshal([]byte(jsonContent), &response)
		if err == nil {
			finalAnalysis, err = r.extractFinalAnalysisFromMap(response)
			if err == nil {
				return finalAnalysis, nil
			}
		}
	}
	
	// 策略3：尝试提取多个JSON对象
	jsonObjects := r.extractAllJSONObjects(content)
	for _, jsonObj := range jsonObjects {
		err = json.Unmarshal([]byte(jsonObj), &response)
		if err == nil {
			finalAnalysis, err = r.extractFinalAnalysisFromMap(response)
			if err == nil {
				return finalAnalysis, nil
			}
		}
	}
	
	// 策略4：尝试从文本中提取结构化信息
	finalAnalysis = r.extractFinalAnalysisFromText(content)
	if finalAnalysis != nil {
		return finalAnalysis, nil
	}
	
	// 如果所有策略都失败，返回详细的错误信息
	return nil, fmt.Errorf("无法解析最终分析JSON，尝试了多种解析策略。响应内容长度: %d, 前100字符: %s", len(content), r.safeSubstring(content, 0, 100))
}

// extractFinalAnalysisFromMap 从map中提取FinalAnalysis
func (r *ReActAuditor) extractFinalAnalysisFromMap(response map[string]interface{}) (*FinalAnalysis, error) {
	// 检查是否包含final_analysis字段
	finalAnalysisData, exists := response["final_analysis"]
	if exists {
		// 将final_analysis转换为JSON字符串，然后解析
		finalAnalysisJSON, err := json.Marshal(finalAnalysisData)
		if err != nil {
			return nil, fmt.Errorf("序列化final_analysis失败: %v", err)
		}

		var finalAnalysis FinalAnalysis
		err = json.Unmarshal(finalAnalysisJSON, &finalAnalysis)
		if err != nil {
			return nil, fmt.Errorf("解析final_analysis失败: %v", err)
		}

		return &finalAnalysis, nil
	}
	
	// 如果没有final_analysis字段，尝试直接解析整个响应
	var finalAnalysis FinalAnalysis
	finalAnalysisJSON, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("序列化响应失败: %v", err)
	}
	
	err = json.Unmarshal(finalAnalysisJSON, &finalAnalysis)
	if err != nil {
		return nil, fmt.Errorf("解析响应为FinalAnalysis失败: %v", err)
	}
	
	// 验证是否包含必要字段
	if finalAnalysis.Summary == "" && len(finalAnalysis.Issues) == 0 {
		return nil, fmt.Errorf("响应中未找到有效的分析结果")
	}
	
	return &finalAnalysis, nil
}

// extractFinalAnalysisFromText 从文本中提取FinalAnalysis信息
func (r *ReActAuditor) extractFinalAnalysisFromText(content string) *FinalAnalysis {
	finalAnalysis := &FinalAnalysis{}
	
	// 尝试提取总结
	summaryPatterns := []string{
		`"summary"\s*:\s*"([^"]*)"`,
		`summary\s*:\s*"([^"]*)"`,
		`总结\s*:\s*"([^"]*)"`,
		`总结\s*:\s*([^"]*)`,
	}
	
	for _, pattern := range summaryPatterns {
		if matches := r.extractWithRegex(content, pattern); len(matches) > 0 {
			finalAnalysis.Summary = matches[0]
			break
		}
	}
	
	// 尝试提取风险等级
	riskPatterns := []string{
		`"risk_level"\s*:\s*"([^"]*)"`,
		`risk_level\s*:\s*"([^"]*)"`,
		`风险等级\s*:\s*"([^"]*)"`,
		`风险等级\s*:\s*([^"]*)`,
	}
	
	for _, pattern := range riskPatterns {
		if matches := r.extractWithRegex(content, pattern); len(matches) > 0 {
			finalAnalysis.RiskLevel = matches[0]
			break
		}
	}
	
	// 尝试提取建议
	recommendationPatterns := []string{
		`"recommendations"\s*:\s*\[(.*?)\]`,
		`recommendations\s*:\s*\[(.*?)\]`,
		`建议\s*:\s*\[(.*?)\]`,
	}
	
	for _, pattern := range recommendationPatterns {
		if matches := r.extractWithRegex(content, pattern); len(matches) > 0 {
			recommendationsStr := matches[0]
			// 简单分割建议
			recommendations := strings.Split(recommendationsStr, ",")
			for _, rec := range recommendations {
				rec = strings.TrimSpace(rec)
				rec = strings.Trim(rec, `"`)
				if rec != "" {
					finalAnalysis.Recommendations = append(finalAnalysis.Recommendations, rec)
				}
			}
			break
		}
	}
	
	// 如果没有找到结构化信息，创建一个基本的分析结果
	if finalAnalysis.Summary == "" {
		// 尝试从内容中提取关键信息作为总结
		if strings.Contains(strings.ToLower(content), "安全") || strings.Contains(strings.ToLower(content), "security") {
			finalAnalysis.Summary = "代码安全分析完成"
		} else {
			finalAnalysis.Summary = "代码分析完成"
		}
	}
	
	if finalAnalysis.RiskLevel == "" {
		finalAnalysis.RiskLevel = "medium" // 默认中等风险
	}
	
	// 如果没有找到建议，添加默认建议
	if len(finalAnalysis.Recommendations) == 0 {
		finalAnalysis.Recommendations = []string{
			"建议进行全面的安全代码审查",
			"建议使用静态代码分析工具",
			"建议定期进行安全培训",
		}
	}
	
	// 创建默认的安全问题
	if len(finalAnalysis.Issues) == 0 {
		finalAnalysis.Issues = []Issue{
			{
				Type:        "代码审计",
				Description: finalAnalysis.Summary,
				Severity:    finalAnalysis.RiskLevel,
				Location:    "代码变更",
				Suggestion:  "建议定期进行安全代码审查",
			},
		}
	}
	
	return finalAnalysis
}

// convertIssuesFromJSON 将JSON格式的问题转换为SecurityIssue格式，并返回额外信息
func (r *ReActAuditor) convertIssuesFromJSON(finalAnalysis *FinalAnalysis, diff string) ([]SecurityIssue, []string, string) {
	var issues []SecurityIssue
	
	for _, issue := range finalAnalysis.Issues {
		// 确定风险等级
		level := "medium" // 默认中等风险
		switch strings.ToLower(issue.Severity) {
		case "high", "critical":
			level = "high"
		case "low", "info":
			level = "low"
		}
		
		// 构建详细的上下文信息，使用大模型生成的内容
		context := fmt.Sprintf("位置: %s, 风险等级: %s", issue.Location, issue.Severity)
		
		// 使用大模型生成的证据
		if issue.Evidence != "" {
			context += fmt.Sprintf("\n证据: %s", issue.Evidence)
		}
		
		// 使用大模型生成的分析上下文
		if issue.AnalysisContext != "" {
			context += fmt.Sprintf("\n分析过程: %s", issue.AnalysisContext)
		} else if finalAnalysis.AnalysisProcess != "" {
			// 如果没有特定的分析上下文，使用通用的分析过程
			context += fmt.Sprintf("\n分析过程: %s", finalAnalysis.AnalysisProcess)
		}
		
		// 从diff中提取文件名
		fileName := extractFileNameFromDiff(diff)
		
		issues = append(issues, SecurityIssue{
			Type:       issue.Type,
			Desc:       issue.Description,
			Code:       FlexibleString(diff),
			Suggestion: issue.Suggestion,
			File:       fileName,
			Level:      level,
			Context:    context,
		})
	}
	
	// 如果没有检测到具体问题，返回一个通用的安全提醒
	if len(issues) == 0 {
		// 从diff中提取文件名
		fileName := extractFileNameFromDiff(diff)
		
		issues = append(issues, SecurityIssue{
			Type:       "代码审计",
			Desc:       finalAnalysis.Summary,
			Code:       FlexibleString(diff),
			Suggestion: "建议定期进行安全代码审查",
			File:       fileName,
			Level:      "low",
			Context:    fmt.Sprintf("整体风险等级: %s", finalAnalysis.RiskLevel),
		})
	}
	
	return issues, finalAnalysis.Recommendations, finalAnalysis.RiskLevel
}

// executeTool 执行工具调用
func (r *ReActAuditor) executeTool(action string, args map[string]interface{}) string {
	if args == nil {
		args = make(map[string]interface{})
	}

	// 记录工具执行的输入
	argsJSON, _ := json.MarshalIndent(args, "", "  ")
	log.Printf("GitLab工具执行输入 - 工具名: %s, 参数: %s", action, string(argsJSON))

	// 根据MCP模式选择执行器
	var result GitLabMCPResult
	
	switch r.mcpMode {
	case "simplified":
		result = SimplifiedGitLabMCPExecutor(GitLabMCPCall{
			ToolName:  action,
			Arguments: args,
		}, r.gitClient, r.projectID)
	case "full":
		// 完整模式使用重试机制和详细日志
		result = r.executeToolWithRetry(action, args)
	default:
		// 默认使用简化版
		result = SimplifiedGitLabMCPExecutor(GitLabMCPCall{
			ToolName:  action,
			Arguments: args,
		}, r.gitClient, r.projectID)
	}

	// 记录工具执行结果
	if result.Error != "" {
		log.Printf("GitLab工具执行失败 - 工具名: %s, 错误: %s", action, result.Error)
		return fmt.Sprintf("工具执行失败: %s", result.Error)
	}

	log.Printf("GitLab工具执行成功 - 工具名: %s, 输出长度: %d", action, len(result.Content))
	
	// 详细记录工具执行结果
	if len(result.Content) > 0 {
		// 尝试解析JSON结果以提供更友好的输出
		var parsedResult interface{}
		if err := json.Unmarshal([]byte(result.Content), &parsedResult); err == nil {
			// 如果是JSON格式，提供结构化输出
			log.Printf("GitLab工具执行结果解析 - 工具名: %s", action)
			if array, ok := parsedResult.([]interface{}); ok {
				log.Printf("  - 找到 %d 个结果", len(array))
				for i, item := range array {
					if i < 3 { // 只显示前3个结果
						if itemMap, ok := item.(map[string]interface{}); ok {
							if line, exists := itemMap["line"]; exists {
								log.Printf("  - 结果 %d: 行号 %v", i+1, line)
							}
							if context, exists := itemMap["context"]; exists {
								if contextStr, ok := context.(string); ok && len(contextStr) > 0 {
									// 显示上下文的前100个字符
									preview := contextStr
									if len(preview) > 100 {
										preview = preview[:100] + "..."
									}
									log.Printf("  - 结果 %d: 上下文 %s", i+1, preview)
								}
							}
						}
					}
				}
				if len(array) > 3 {
					log.Printf("  - ... 还有 %d 个结果", len(array)-3)
				}
			} else {
				// 如果不是数组，显示完整内容（限制长度）
				contentStr := fmt.Sprintf("%v", parsedResult)
				if len(contentStr) > 200 {
					contentStr = contentStr[:200] + "..."
				}
				log.Printf("  - 内容: %s", contentStr)
			}
		} else {
			// 如果不是JSON格式，显示原始内容（限制长度）
			contentPreview := result.Content
			if len(contentPreview) > 200 {
				contentPreview = contentPreview[:200] + "..."
			}
			log.Printf("  - 原始内容: %s", contentPreview)
		}
	}

	return result.Content
}

// executeToolWithRetry 带重试机制的工具执行（完整模式）
func (r *ReActAuditor) executeToolWithRetry(action string, args map[string]interface{}) GitLabMCPResult {
	call := GitLabMCPCall{
		ToolName:  action,
		Arguments: args,
	}

	// 记录工具执行的输入
	argsJSON, _ := json.MarshalIndent(args, "", "  ")
	log.Printf("GitLab工具执行输入 - 工具名: %s, 参数: %s", action, string(argsJSON))

	// 检查是否有GitLab客户端
	if r.gitClient == nil {
		log.Printf("GitLab工具执行失败 - GitLab客户端为空")
		return GitLabMCPResult{Error: "GitLab客户端未初始化"}
	}

	// 使用GitLab API执行工具（带重试机制）
	var result GitLabMCPResult
	
	for retry := 0; retry <= r.maxRetries; retry++ {
		if retry > 0 {
			log.Printf("GitLab工具执行重试 - 工具名: %s, 重试次数: %d", action, retry)
			time.Sleep(time.Duration(retry) * time.Second) // 递增延迟
		}
		
		result = GitLabMCPExecutor(call, r.gitClient, r.projectID)
		
		// 如果成功或非重试性错误，跳出循环
		if result.Error == "" || !isRetryableError(result.Error) {
			break
		}
		
		log.Printf("GitLab工具执行失败，准备重试 - 工具名: %s, 错误: %s", action, result.Error)
	}
	
	// 记录工具执行的输出
	if result.Error != "" {
		log.Printf("GitLab工具执行失败 - 工具名: %s, 错误: %s", action, result.Error)
		
		// 提供更友好的错误信息和建议
		errorMsg := fmt.Sprintf("工具执行失败: %s", result.Error)
		
		// 针对常见错误提供具体建议
		if strings.Contains(result.Error, "超出文件范围") {
			errorMsg += "\n建议：先使用 gitlab_file_info 工具获取文件信息，了解文件行数后再进行分析"
		} else if strings.Contains(result.Error, "无法找到文件") {
			errorMsg += "\n建议：检查文件路径是否正确，或使用 gitlab_search_code 工具搜索相关文件"
		} else if strings.Contains(result.Error, "获取项目信息失败") {
			errorMsg += "\n建议：检查项目ID和GitLab访问权限"
		}
		
		return GitLabMCPResult{Error: errorMsg}
	}

	log.Printf("GitLab工具执行成功 - 工具名: %s, 输出长度: %d", action, len(result.Content))
	
	// 详细记录工具执行结果
	if len(result.Content) > 0 {
		// 尝试解析JSON结果以提供更友好的输出
		var parsedResult interface{}
		if err := json.Unmarshal([]byte(result.Content), &parsedResult); err == nil {
			// 如果是JSON格式，提供结构化输出
			log.Printf("GitLab工具执行结果解析 - 工具名: %s", action)
			if array, ok := parsedResult.([]interface{}); ok {
				log.Printf("  - 找到 %d 个结果", len(array))
				for i, item := range array {
					if i < 3 { // 只显示前3个结果
						if itemMap, ok := item.(map[string]interface{}); ok {
							if line, exists := itemMap["line"]; exists {
								log.Printf("  - 结果 %d: 行号 %v", i+1, line)
							}
							if context, exists := itemMap["context"]; exists {
								if contextStr, ok := context.(string); ok && len(contextStr) > 0 {
									// 显示上下文的前100个字符
									preview := contextStr
									if len(preview) > 100 {
										preview = preview[:100] + "..."
									}
									log.Printf("  - 结果 %d: 上下文 %s", i+1, preview)
								}
							}
						}
					}
				}
				if len(array) > 3 {
					log.Printf("  - ... 还有 %d 个结果", len(array)-3)
				}
			} else {
				// 如果不是数组，显示完整内容（限制长度）
				if len(result.Content) > 500 {
					log.Printf("GitLab工具执行输出预览 - 工具名: %s, 输出: %s...", action, result.Content[:500])
				} else {
					log.Printf("GitLab工具执行输出 - 工具名: %s, 输出: %s", action, result.Content)
				}
			}
		} else {
			// 如果不是JSON格式，显示原始内容
			if len(result.Content) > 500 {
				log.Printf("GitLab工具执行输出预览 - 工具名: %s, 输出: %s...", action, result.Content[:500])
			} else {
				log.Printf("GitLab工具执行输出 - 工具名: %s, 输出: %s", action, result.Content)
			}
		}
	} else {
		log.Printf("GitLab工具执行结果为空 - 工具名: %s", action)
	}

	return result
}

// isRetryableError 判断错误是否可重试
func isRetryableError(errorMsg string) bool {
	retryableErrors := []string{
		"rate limit",
		"429",
		"timeout",
		"connection refused",
		"network error",
		"temporary failure",
	}
	
	for _, retryableError := range retryableErrors {
		if strings.Contains(strings.ToLower(errorMsg), retryableError) {
			return true
		}
	}
	return false
}

// extractSecurityIssues 从最终答案中提取安全问题
func (r *ReActAuditor) extractSecurityIssues(finalAnswer, diff string) []SecurityIssue {
	// 使用正则表达式或关键词匹配提取安全问题
	// 这里简化处理，实际可以更复杂
	var issues []SecurityIssue

	// 简单的关键词匹配
	keywords := map[string]string{
		"sql注入": "SQL注入",
		"sql injection": "SQL注入",
		"xss": "XSS",
		"跨站脚本": "XSS",
		"csrf": "CSRF",
		"命令注入": "命令注入",
		"command injection": "命令注入",
		"路径遍历": "路径遍历",
		"path traversal": "路径遍历",
		"敏感信息": "敏感信息泄露",
		"sensitive": "敏感信息泄露",
		"认证": "认证缺陷",
		"authorization": "授权缺陷",
		"权限": "权限缺陷",
	}

	for keyword, issueType := range keywords {
		if strings.Contains(strings.ToLower(finalAnswer), strings.ToLower(keyword)) {
			// 从diff中提取文件名
			fileName := extractFileNameFromDiff(diff)
			
			issues = append(issues, SecurityIssue{
				Type:       issueType,
				Desc:       fmt.Sprintf("检测到%s相关风险", issueType),
				Code:       FlexibleString(diff),
				Suggestion: "请详细检查相关代码逻辑",
				File:       fileName,
				Level:      "medium", // 默认中等风险
				Context:    finalAnswer,
			})
		}
	}

	// 如果没有检测到具体问题，返回一个通用的安全提醒
	if len(issues) == 0 {
		// 从diff中提取文件名
		fileName := extractFileNameFromDiff(diff)
		
		issues = append(issues, SecurityIssue{
			Type:       "代码审计",
			Desc:       "代码变更已通过安全审计",
			Code:       FlexibleString(diff),
			Suggestion: "建议定期进行安全代码审查",
			File:       fileName,
			Level:      "low",
			Context:    finalAnswer,
		})
	}

	return issues
}



// GetMaxSteps 获取最大步骤数
func (r *ReActAuditor) GetMaxSteps() int {
	return r.maxSteps
}

// extractFileNameFromDiff 从diff中提取文件名
func extractFileNameFromDiff(diff string) string {
	lines := strings.Split(diff, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "File: ") {
			fileName := strings.TrimPrefix(line, "File: ")
			fileName = strings.TrimSpace(fileName)
			if fileName != "" {
				return fileName
			}
		}
	}
	
	return ""
} 