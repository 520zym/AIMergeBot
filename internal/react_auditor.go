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

	return fmt.Sprintf(`你是一个专业的代码安全审计专家，使用ReAct（Reasoning and Acting）方法进行代码分析。

可用工具：
%s

ReAct格式要求：
1. 每个响应必须包含以下字段：
   - thought: 你的思考过程
   - action: 要执行的动作（可选，如果不需要调用工具则为空）
   - action_args: 动作参数（可选）
   - observation: 观察结果（由系统填充）
   - 在得出最终结论前，必须调用工具多分析一步上下文

2. 如果这是最终答案，必须输出以下JSON格式：
{
  "thought": "这是最终答案，分析总结...",
  "action": "",
  "action_args": {},
  "observation": "",
  "final_analysis": {
    "summary": "整体安全评估总结",
    "issues": [
      {
        "type": "安全问题类型",
        "description": "详细描述",
        "severity": "high/medium/low",
        "location": "问题位置",
        "suggestion": "修复建议"
      }
    ],
    "risk_level": "overall_risk_level",
    "recommendations": ["建议1", "建议2"]
  }
}

3. 分析重点：
   - SQL注入、XSS、CSRF、命令注入
   - 路径遍历、敏感信息泄露
   - 认证与授权缺陷、SSRF
   - 反序列化、文件上传/下载
   - 任意代码执行、依赖包安全
   - 业务安全漏洞

4. 使用工具获取更多上下文信息，深入分析代码逻辑。

请严格按照JSON格式输出，不要包含其他文本。`, string(toolsJSON))
}

// buildInitialPrompt 构建初始用户提示
func (r *ReActAuditor) buildInitialPrompt(diff string, projectInfo map[string]interface{}) string {
	return fmt.Sprintf(`请分析以下代码变更的安全风险：

项目信息：
- 项目ID: %v
- 项目名称: %v
- 分支: %v

代码变更：
%s

请使用ReAct方法进行分析：
1. 首先理解代码变更的内容和目的
2. 识别潜在的安全风险点
3. 使用可用工具获取更多上下文信息
4. 深入分析每个风险点
5. 给出最终的安全评估报告

开始分析：`, 
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
	Summary        string   `json:"summary"`
	Issues         []Issue  `json:"issues"`
	RiskLevel      string   `json:"risk_level"`
	Recommendations []string `json:"recommendations"`
}

// Issue 定义安全问题结构
type Issue struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Location    string `json:"location"`
	Suggestion  string `json:"suggestion"`
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
		
		issues = append(issues, SecurityIssue{
			Type:       issue.Type,
			Desc:       issue.Description,
			Code:       FlexibleString(diff),
			Suggestion: issue.Suggestion,
			Level:      level,
			Context:    fmt.Sprintf("位置: %s, 风险等级: %s", issue.Location, issue.Severity),
		})
	}
	
	// 如果没有检测到具体问题，返回一个通用的安全提醒
	if len(issues) == 0 {
		issues = append(issues, SecurityIssue{
			Type:       "代码审计",
			Desc:       finalAnalysis.Summary,
			Code:       FlexibleString(diff),
			Suggestion: "建议定期进行安全代码审查",
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

	// 使用GitLab API执行工具
	result := GitLabMCPExecutor(call, r.gitClient, r.projectID)
	
	// 记录工具执行的输出
	if result.Error != "" {
		log.Printf("GitLab工具执行失败 - 工具名: %s, 错误: %s", action, result.Error)
		return fmt.Sprintf("工具执行失败: %s", result.Error)
	}

	log.Printf("GitLab工具执行成功 - 工具名: %s, 输出长度: %d", action, len(result.Content))
	// 如果输出内容过长，只记录前500个字符
	if len(result.Content) > 500 {
		log.Printf("GitLab工具执行输出预览 - 工具名: %s, 输出: %s...", action, result.Content[:500])
	} else {
		log.Printf("GitLab工具执行输出 - 工具名: %s, 输出: %s", action, result.Content)
	}

	return result.Content
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
			issues = append(issues, SecurityIssue{
				Type:       issueType,
				Desc:       fmt.Sprintf("检测到%s相关风险", issueType),
				Code:       FlexibleString(diff),
				Suggestion: "请详细检查相关代码逻辑",
				Level:      "medium", // 默认中等风险
				Context:    finalAnswer,
			})
		}
	}

	// 如果没有检测到具体问题，返回一个通用的安全提醒
	if len(issues) == 0 {
		issues = append(issues, SecurityIssue{
			Type:       "代码审计",
			Desc:       "代码变更已通过安全审计",
			Code:       FlexibleString(diff),
			Suggestion: "建议定期进行安全代码审查",
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