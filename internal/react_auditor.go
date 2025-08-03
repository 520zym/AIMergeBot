package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
		client:   client,
		model:    model,
		repoPath: repoPath,
		maxSteps: 10, // 最大推理步骤数
	}
}

// NewReActAuditorWithGitLab 创建支持GitLab API的ReAct审计器
func NewReActAuditorWithGitLab(apiKey, baseURL, model string, gitClient *gitlab.Client, projectID int) *ReActAuditor {
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
		client:    client,
		model:     model,
		repoPath:  "",
		maxSteps:  10, // 最大推理步骤数
		gitClient: gitClient,
		projectID: projectID,
	}
}

// AuditWithReAct 使用ReAct方法进行代码审计
func (r *ReActAuditor) AuditWithReAct(diff string, projectInfo map[string]interface{}) (*ReActAuditResult, error) {
	result := &ReActAuditResult{
		Steps: make([]ReActStep, 0),
	}

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
		maxRetries := 3
		
		for retry := 0; retry < maxRetries; retry++ {
			if retry > 0 {
				log.Printf("ReAct步骤 %d - 重试第 %d 次", step+1, retry)
				time.Sleep(time.Duration(retry) * time.Second) // 递增延迟
			}
			
			resp, err = r.client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
				Model:    r.model,
				Messages: messages,
				Temperature: 0.1, // 降低随机性，提高一致性
			})
			
			if err == nil {
				break // 成功，跳出重试循环
			}
			
			log.Printf("ReAct步骤 %d - 大模型调用失败 (重试 %d/%d): %v", step+1, retry+1, maxRetries, err)
			
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

		result.Steps = append(result.Steps, *reactStep)

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
	}

	return result, nil
}

// buildSystemPrompt 构建系统提示
func (r *ReActAuditor) buildSystemPrompt() string {
	tools := GetAvailableGitLabTools()
	toolsJSON, _ := json.MarshalIndent(tools, "", "  ")

	return fmt.Sprintf(`你是一个专业的白盒代码安全审计专家，使用ReAct（Reasoning and Acting）方法进行深度代码安全分析。

## 可用工具：
%s

## ReAct格式要求：
1. 每个响应必须包含以下字段：
   - thought: 你的思考过程（详细说明当前分析思路和下一步计划）
   - action: 要执行的动作（可选，如果不需要调用工具则为空）
   - action_args: 动作参数（可选）
   - observation: 观察结果（由系统填充）
   - 在得出最终结论前，必须调用工具多分析一步上下文

2. **详细推理要求**：
   - 在thought中详细说明为什么要调用特定工具
   - 解释工具参数的选择原因（如context_lines、search_type等）
   - 在最终答案中详细说明如何基于工具结果得出结论
   - 提供具体的代码位置和问题描述
   - **为每个问题生成独特的证据和分析上下文**
   - **基于工具调用结果，为每个问题提供具体的发现过程**
   - **确保每个问题的evidence和analysis_context都是独特的，反映具体的工具调用结果**

2. 如果这是最终答案，必须输出以下JSON格式：
{
  "thought": "这是最终答案，基于所有工具调用结果进行综合分析...",
  "action": "",
  "action_args": {},
  "observation": "",
  "final_analysis": {
    "summary": "整体安全评估总结（基于具体工具结果）",
    "issues": [
      {
        "type": "安全问题类型",
        "description": "详细描述（包含具体代码位置和问题原因）",
        "severity": "high/medium/low",
        "location": "具体文件路径和行号",
        "suggestion": "具体的修复建议（包含代码示例）",
        "evidence": "支持该问题的具体证据（基于工具调用结果，每个问题都要有独特的证据）",
        "analysis_context": "该问题的独特分析上下文（基于工具调用结果，说明如何发现和确认这个问题）"
      }
    ],
    "risk_level": "overall_risk_level",
    "recommendations": ["具体建议1", "具体建议2"],
    "analysis_process": "详细说明分析过程和工具使用情况"
  }
}

## 白盒代码审计重点：

### 1. 输入验证与过滤
- 检查用户输入是否经过proper验证
- 查找SQL注入、XSS、命令注入等漏洞
- 分析输入过滤逻辑的完整性
- 检查参数化查询的使用

### 2. 认证与授权
- 分析认证流程的安全性
- 检查权限控制逻辑
- 查找认证绕过漏洞
- 分析会话管理机制

### 3. 敏感信息处理
- 查找硬编码的密码、密钥、Token
- 检查敏感信息的传输和存储
- 分析加密算法的使用
- 检查日志中的敏感信息泄露

### 4. 文件操作安全
- 检查路径遍历漏洞
- 分析文件上传/下载的安全性
- 检查文件权限控制
- 分析临时文件处理

### 5. 网络通信安全
- 检查SSRF漏洞
- 分析网络请求的安全性
- 检查HTTPS的使用
- 分析API端点的安全性

### 6. 业务逻辑安全
- 检查业务逻辑漏洞
- 分析并发安全问题
- 检查竞态条件
- 分析业务规则绕过

### 7. 依赖安全
- 检查第三方依赖的安全漏洞
- 分析依赖版本的安全性
- 检查过时的依赖包
- 分析依赖的权限要求

### 8. 错误处理与日志
- 检查错误信息泄露
- 分析异常处理的安全性
- 检查日志记录的安全性
- 分析调试信息的泄露

### 9. 创新性安全发现
- **不要局限于预定义的安全模式**
- **主动发现新的安全漏洞类型**
- **分析代码逻辑中的潜在风险**
- **识别业务场景特有的安全问题**
- **发现框架或库的特定安全风险**
- **分析代码架构的安全缺陷**
- **识别新兴的安全威胁模式**

## 分析策略：

1. **深度分析**：使用工具获取更多上下文信息，深入分析代码逻辑
2. **关联分析**：将发现的问题与相关代码关联，理解攻击面
3. **风险评估**：根据漏洞类型、影响范围、利用难度评估风险等级
4. **修复建议**：提供具体、可操作的修复建议，包括代码示例
5. **最佳实践**：推荐安全编码最佳实践和防护措施
6. **创新发现**：**主动寻找预定义规则之外的安全问题**
7. **业务分析**：**结合业务场景分析特有的安全风险**
8. **架构审查**：**从整体架构角度发现安全缺陷**

## 工具使用指导：

### 智能工具调用策略：
1. **首先使用 gitlab_file_info** 获取文件基本信息（行数、类型等）
2. **然后使用 gitlab_context_analysis** 进行详细分析，根据文件行数智能选择行号
3. **使用 gitlab_search_code** 搜索特定的安全模式或代码片段
4. **使用 gitlab_file_content** 获取完整文件内容进行综合分析

### 上下文长度智能配置：
- **简单搜索**：context_lines=5（快速定位）
- **函数分析**：context_lines=10（查看函数定义和调用）
- **复杂逻辑**：context_lines=15-20（深入分析业务逻辑）
- **安全审计**：context_lines=20-30（全面安全分析）
- **依赖分析**：context_lines=10（查看导入和依赖关系）

### 行号选择策略：
- **小文件（<50行）**：选择中间行或关键行进行分析
- **中等文件（50-200行）**：选择函数定义、主要逻辑行进行分析
- **大文件（>200行）**：先获取文件信息，然后选择关键行进行分析
- **避免边界行号**：不要选择第1行或最后几行，除非有特殊需要

### 工具使用最佳实践：
- 使用 gitlab_file_info 了解文件结构后再进行详细分析
- 使用 gitlab_enhanced_code_search 进行智能搜索，根据分析深度配置context_lines
- 使用 gitlab_function_analysis 深入分析特定函数的安全性
- 使用 gitlab_context_analysis 获取特定代码行的详细上下文
- 使用 gitlab_security_audit 进行综合安全审计

### 核心安全分析工具：
- **gitlab_security_pattern_search**: 搜索特定安全漏洞模式（SQL注入、XSS、命令注入等）
- **gitlab_function_analysis**: 分析函数的完整定义、调用关系、参数传递
- **gitlab_dependency_analysis**: 分析项目依赖的安全风险
- **gitlab_config_analysis**: 分析配置文件中的安全问题
- **gitlab_data_flow_analysis**: 追踪数据流，识别数据泄露风险
- **gitlab_api_endpoint_analysis**: 分析API端点的安全控制
- **gitlab_error_handling_analysis**: 分析错误处理机制的安全风险
- **gitlab_authentication_analysis**: 分析认证授权机制
- **gitlab_file_operation_analysis**: 分析文件操作的安全性
- **gitlab_network_operation_analysis**: 分析网络操作的安全风险

### 安全分析策略：
1. **漏洞模式搜索**: 使用 gitlab_security_pattern_search 搜索常见漏洞模式
2. **函数深度分析**: 使用 gitlab_function_analysis 分析关键函数的安全性
3. **依赖安全检查**: 使用 gitlab_dependency_analysis 检查第三方依赖风险
4. **配置安全审查**: 使用 gitlab_config_analysis 检查配置文件问题
5. **数据流追踪**: 使用 gitlab_data_flow_analysis 追踪敏感数据流
6. **API安全审计**: 使用 gitlab_api_endpoint_analysis 审计API端点
7. **错误处理检查**: 使用 gitlab_error_handling_analysis 检查错误信息泄露
8. **认证机制分析**: 使用 gitlab_authentication_analysis 分析认证流程
9. **文件操作审计**: 使用 gitlab_file_operation_analysis 检查文件操作安全
10. **网络操作检查**: 使用 gitlab_network_operation_analysis 检查网络请求安全

### 文件内容处理策略：
- **如果文件内容与期望不符**：检查文件路径、分支信息是否正确
- **如果文件很小（<20行）**：工具会自动返回完整内容，直接分析即可
- **如果行号超出范围**：工具会自动调整并返回相关内容，注意查看调整信息
- **如果文件不存在**：使用 gitlab_search_code 搜索相关文件
- **如果分支信息错误**：尝试不同的分支名称（main、master、develop等）

### 分析策略调整：
- **当工具返回完整内容时**：直接基于完整内容进行安全分析
- **当工具返回调整信息时**：理解调整原因，基于实际返回的内容进行分析
- **当文件内容与diff不一致时**：可能是分支或文件路径问题，尝试其他分支或搜索相关文件

## 输出要求：

1. **结构化分析**：按安全领域分类分析结果
2. **风险分级**：明确标注每个问题的风险等级
3. **具体建议**：提供可操作的修复建议
4. **代码示例**：提供安全的代码实现示例
5. **最佳实践**：推荐相关的安全最佳实践
6. **独特证据**：**每个问题都要有独特的evidence，基于具体的工具调用结果**
7. **个性化分析**：**每个问题都要有独特的analysis_context，说明如何发现和确认该问题**
8. **具体位置**：**每个问题都要有具体的文件路径和行号**

请严格按照JSON格式输出，不要包含其他文本。`, string(toolsJSON))
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

## 审计要求：

### 第一阶段：初步分析
1. 理解代码变更的目的和功能
2. 识别变更涉及的安全敏感区域
3. 确定需要深入分析的关键点

### 第二阶段：深度审计
1. **输入验证审计**
   - 检查用户输入的处理方式
   - 查找潜在的注入漏洞
   - 分析输入过滤和验证逻辑

2. **认证授权审计**
   - 分析认证流程的安全性
   - 检查权限控制机制
   - 查找认证绕过漏洞

3. **敏感信息审计**
   - 查找硬编码的敏感信息
   - 检查敏感数据的传输和存储
   - 分析加密和哈希的使用

4. **文件操作审计**
   - 检查文件操作的路径处理
   - 分析文件权限控制
   - 查找路径遍历漏洞

5. **网络通信审计**
   - 检查网络请求的安全性
   - 分析API端点的安全控制
   - 查找SSRF漏洞

6. **业务逻辑审计**
   - 分析业务逻辑的安全性
   - 检查并发安全问题
   - 查找业务规则绕过

7. **依赖安全审计**
   - 检查第三方依赖的安全性
   - 分析依赖版本的风险
   - 查找已知漏洞的依赖

8. **错误处理审计**
   - 检查错误信息的泄露
   - 分析异常处理的安全性
   - 查找调试信息泄露

### 第三阶段：综合评估
1. 评估整体安全风险等级
2. 提供具体的修复建议
3. 推荐安全最佳实践

## 使用工具策略：

1. **使用 gitlab_search_security_patterns** 搜索特定类型的安全漏洞
2. **使用 gitlab_analyze_dependencies** 检查依赖安全
3. **使用 gitlab_search_config_files** 查找敏感配置
4. **使用 gitlab_analyze_auth_flow** 分析认证流程
5. **使用 gitlab_search_api_endpoints** 检查API安全性
6. **使用 gitlab_analyze_file_operations** 检查文件操作安全
7. **使用 gitlab_search_encryption_usage** 分析加密实现
8. **使用 gitlab_analyze_input_validation** 检查输入验证
9. **使用 gitlab_search_error_handling** 检查错误处理
10. **使用 gitlab_analyze_network_operations** 检查网络操作
11. **使用 gitlab_search_business_logic** 检查业务逻辑安全

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

请开始深度安全审计：`, 
		projectInfo["project_id"], 
		projectInfo["project_name"], 
		projectInfo["branch"], 
		diff)
}

// parseReActResponse 解析ReAct格式的响应
func (r *ReActAuditor) parseReActResponse(content string) (*ReActStep, bool, error) {
	// 尝试解析JSON格式
	var step ReActStep
	err := json.Unmarshal([]byte(content), &step)
	if err != nil {
		// 如果不是标准JSON，尝试提取JSON部分
		jsonStart := strings.Index(content, "{")
		jsonEnd := strings.LastIndex(content, "}")
		if jsonStart >= 0 && jsonEnd > jsonStart {
			jsonContent := content[jsonStart:jsonEnd+1]
			err = json.Unmarshal([]byte(jsonContent), &step)
		}
		if err != nil {
			return nil, false, fmt.Errorf("无法解析ReAct响应: %v", err)
		}
	}

	// 检查是否为最终答案
	isFinal := strings.Contains(strings.ToLower(step.Thought), "最终答案") || 
			   strings.Contains(strings.ToLower(step.Thought), "final answer") ||
			   step.Action == ""

	return &step, isFinal, nil
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
	// 尝试解析JSON格式
	var response map[string]interface{}
	err := json.Unmarshal([]byte(content), &response)
	if err != nil {
		// 如果不是标准JSON，尝试提取JSON部分
		jsonStart := strings.Index(content, "{")
		jsonEnd := strings.LastIndex(content, "}")
		if jsonStart >= 0 && jsonEnd > jsonStart {
			jsonContent := content[jsonStart:jsonEnd+1]
			err = json.Unmarshal([]byte(jsonContent), &response)
		}
		if err != nil {
			return nil, fmt.Errorf("无法解析最终分析JSON: %v", err)
		}
	}

	// 检查是否包含final_analysis字段
	finalAnalysisData, exists := response["final_analysis"]
	if !exists {
		return nil, fmt.Errorf("响应中未找到final_analysis字段")
	}

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
		return "工具执行失败: GitLab客户端未初始化"
	}

	// 使用GitLab API执行工具（带重试机制）
	var result GitLabMCPResult
	maxRetries := 2
	
	for retry := 0; retry <= maxRetries; retry++ {
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
		
		return errorMsg
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

	// 解析工具调用结果，提取有用的信息
	var toolResults []map[string]interface{}
	if len(result.Content) > 0 {
		var parsedResult interface{}
		if err := json.Unmarshal([]byte(result.Content), &parsedResult); err == nil {
			if array, ok := parsedResult.([]interface{}); ok {
				for _, item := range array {
					if itemMap, ok := item.(map[string]interface{}); ok {
						// 提取关键信息
						toolResult := make(map[string]interface{})
						if line, exists := itemMap["line"]; exists {
							toolResult["line"] = line
						}
						if context, exists := itemMap["context"]; exists {
							toolResult["context"] = context
						}
						if name, exists := itemMap["name"]; exists {
							toolResult["name"] = name
						}
						if path, exists := itemMap["path"]; exists {
							toolResult["path"] = path
						}
						toolResults = append(toolResults, toolResult)
					}
				}
			} else if mapResult, ok := parsedResult.(map[string]interface{}); ok {
				// 处理单个对象结果
				toolResult := make(map[string]interface{})
				for key, value := range mapResult {
					toolResult[key] = value
				}
				toolResults = append(toolResults, toolResult)
			}
		}
	}

	return result.Content
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