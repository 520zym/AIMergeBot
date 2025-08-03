package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/sashabaranov/go-openai"
)

func AnalyzeDiffWithOpenAI(apiKey, diff, baseURL, model string) ([]SecurityIssue, error) {
	var client *openai.Client
	if baseURL != "" {
		cfg := openai.DefaultConfig(apiKey)
		cfg.BaseURL = baseURL
		client = openai.NewClientWithConfig(cfg)
	} else {
		client = openai.NewClient(apiKey)
	}
	if model == "" {
		model = openai.GPT3Dot5Turbo
	}
	prompt := `你是 PR-Reviewer，一个专注于审查 Git Pull Request（PR）安全漏洞的专业语言模型。请严格按照如下要求输出：

【输出要求】
- 只分析 diff 中新增的代码（以 '+' 开头的行）。
- 输出一个 JSON 数组，每个元素为一个安全问题，字段如下：
  - type: 风险类型（如 SQL注入、XSS、CSRF、敏感信息泄露等）
  - desc: 简要描述风险点
  - code: 相关代码片段（可多行）
  - suggestion: 修复建议
  - file: 文件名（必须从diff中的"File: "行提取，如"File: main.go"则file字段应为"main.go"）
  - level: 风险等级（high/medium/low）
  - context: 相关上下文说明（如变量来源、调用链、业务背景等）
- 如果没有任何安全问题，输出空数组 []。

【分析要求】
1. 逐行分析所有新增代码，尤其关注 SQL 注入、XSS、CSRF、命令注入、路径遍历、敏感信息泄露、认证与授权缺陷、SSRF、反序列化、文件上传/下载、任意代码执行、依赖包安全、业务安全等。
2. 对每一类风险，结合上下文和代码实际用途，判断是否存在漏洞或隐患。
3. 对于疑似风险（如用户输入未经过滤直接拼接到 SQL/命令/路径/HTML/JS），也要指出并说明理由。
4. 对于敏感信息泄露，需识别硬编码的密钥、密码、Token、证书、私钥、配置等。
5. 对于认证、鉴权、权限控制相关代码，需判断是否存在越权、未鉴权、权限绕过等问题。
6. 对于依赖包变更，需判断是否引入了已知有漏洞的依赖。
7. 对于业务逻辑相关变更，需关注是否存在业务越权、刷单、接口未鉴权等问题。
8. 对于所有安全问题，需给出具体的代码片段、风险点说明和修复建议。
9. 风险等级 level 按高危（high）、中危（medium）、低危（low）分级。
10. context 字段补充变量来源、调用链、业务背景等有助于理解风险的上下文。
11. 文件名解析：diff中每段都以"File: 文件名"开头，必须从该行提取文件名填入file字段，不要留空。

【示例输出】
[
  {
    "type": "SQL注入",
    "desc": "用户输入未经过滤直接拼接到SQL查询，存在注入风险。",
    "code": "+ query := \"SELECT * FROM users WHERE id = '" + userInput + "'\"",
    "suggestion": "使用参数化查询或ORM安全接口，禁止拼接SQL。",
    "file": "main.go",
    "level": "high",
    "context": "userInput来源于外部请求，未做过滤。"
  }
]

注意：如果diff中有"File: b.go"，则file字段必须填写"b.go"，不能为空或"未知文件"。

PR 代码差异：
` + diff
	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
	})
	if err != nil {
		return nil, err
	}
	var issues []SecurityIssue
	if len(resp.Choices) > 0 {
		// 兼容 AI 可能返回代码块包裹的 JSON
		content := resp.Choices[0].Message.Content
		content = trimCodeBlock(content)
		err = json.Unmarshal([]byte(content), &issues)
		if err != nil {
			return nil, err
		}
	}
	
	// 后处理：确保文件名不为空，从diff中提取文件名
	issues = postProcessFileNames(issues, diff)
	
	return issues, nil
}

func generateFixSuggestion(apiKey, baseURL, model string, issue SecurityIssue) (string, error) {
	var client *openai.Client
	if baseURL != "" {
		cfg := openai.DefaultConfig(apiKey)
		cfg.BaseURL = baseURL
		client = openai.NewClientWithConfig(cfg)
	} else {
		client = openai.NewClient(apiKey)
	}
	if model == "" {
		model = openai.GPT3Dot5Turbo
	}

	// 修改后的prompt，要求AI自动识别代码语言
	prompt := fmt.Sprintf(`你是代码安全专家，请基于以下安全问题生成具体的修复代码：

【安全问题详情】
- 类型: %s
- 描述: %s
- 风险等级: %s
- 问题代码: %s
- 上下文: %s

【要求】
1. 提供修复后的完整代码片段，代码块请用正确的语言标注（如go、python、js、java、c等），不要写死为go
2. 说明修复原理和思路
3. 提供测试建议
4. 代码风格应符合该语言最佳实践

【输出格式】
请按以下格式输出：

**修复代码：**
`+"```"+`(请自动识别并填写代码语言，如go、python、js、java、c等)
// 修复后的代码
`+"```"+`

**修复说明：**
详细说明修复原理和思路

**测试建议：**
提供测试用例和验证方法

**注意事项：**
其他需要注意的点

请开始生成修复建议：`, issue.Type, issue.Desc, issue.Level, issue.Code, issue.Context)

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
	})
	if err != nil {
		return "", err
	}

	if len(resp.Choices) > 0 {
		return resp.Choices[0].Message.Content, nil
	}
	return "", fmt.Errorf("AI未返回修复建议")
}

func trimCodeBlock(s string) string {
	if len(s) > 8 && s[:3] == "```" {
		// 去除 markdown 代码块包裹
		return s[7 : len(s)-3]
	}
	return s
}

// postProcessFileNames 后处理文件名，确保不为空
func postProcessFileNames(issues []SecurityIssue, diff string) []SecurityIssue {
	log.Printf("开始后处理文件名，issues数量: %d", len(issues))
	
	// 从diff中提取所有文件名
	fileNames := extractFileNamesFromDiff(diff)
	log.Printf("从diff中提取到文件名: %v", fileNames)
	
	// 检查当前issues的文件名状态
	for i, issue := range issues {
		log.Printf("Issue %d: 类型=%s, 文件名=%s", i+1, issue.Type, issue.File)
	}
	
	// 如果只有一个文件，所有空文件名的issue都使用这个文件名
	if len(fileNames) == 1 {
		log.Printf("只有一个文件，所有空文件名的issue使用: %s", fileNames[0])
		for i := range issues {
			if issues[i].File == "" {
				issues[i].File = fileNames[0]
				log.Printf("修复Issue %d的文件名为: %s", i+1, fileNames[0])
			}
		}
		return issues
	}
	
	// 如果有多个文件，尝试根据代码内容匹配文件名
	log.Printf("有多个文件，尝试智能匹配")
	for i := range issues {
		if issues[i].File == "" {
			// 尝试根据代码内容匹配文件名
			matchedFile := matchFileByCode(string(issues[i].Code), fileNames)
			if matchedFile != "" {
				issues[i].File = matchedFile
				log.Printf("Issue %d智能匹配到文件: %s", i+1, matchedFile)
			} else if len(fileNames) > 0 {
				// 如果无法匹配，使用第一个文件名
				issues[i].File = fileNames[0]
				log.Printf("Issue %d使用默认文件: %s", i+1, fileNames[0])
			}
		}
	}
	
	// 检查后处理结果
	for i, issue := range issues {
		log.Printf("后处理后Issue %d: 类型=%s, 文件名=%s", i+1, issue.Type, issue.File)
	}
	
	return issues
}

// extractFileNamesFromDiff 从diff中提取文件名
func extractFileNamesFromDiff(diff string) []string {
	var fileNames []string
	lines := strings.Split(diff, "\n")
	
	log.Printf("开始解析diff，总行数: %d", len(lines))
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "File: ") {
			fileName := strings.TrimPrefix(line, "File: ")
			fileName = strings.TrimSpace(fileName)
			if fileName != "" {
				fileNames = append(fileNames, fileName)
				log.Printf("第%d行找到文件名: %s", i+1, fileName)
			}
		}
	}
	
	log.Printf("总共提取到 %d 个文件名", len(fileNames))
	return fileNames
}

// matchFileByCode 根据代码内容匹配文件名
func matchFileByCode(code string, fileNames []string) string {
	// 简单的匹配逻辑：根据文件扩展名匹配
	codeLower := strings.ToLower(code)
	
	for _, fileName := range fileNames {
		ext := getFileExtension(fileName)
		if ext != "" {
			// 根据扩展名匹配代码语言特征
			if matchesLanguage(codeLower, ext) {
				return fileName
			}
		}
	}
	
	return ""
}

// getFileExtension 获取文件扩展名
func getFileExtension(fileName string) string {
	parts := strings.Split(fileName, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return ""
}

// matchesLanguage 检查代码是否匹配特定语言
func matchesLanguage(code string, ext string) bool {
	switch ext {
	case "go":
		return strings.Contains(code, "package ") || strings.Contains(code, "func ") || strings.Contains(code, "import ")
	case "py":
		return strings.Contains(code, "import ") || strings.Contains(code, "def ") || strings.Contains(code, "class ")
	case "js":
		return strings.Contains(code, "function ") || strings.Contains(code, "const ") || strings.Contains(code, "let ") || strings.Contains(code, "var ")
	case "java":
		return strings.Contains(code, "public class ") || strings.Contains(code, "import ") || strings.Contains(code, "public static")
	case "c":
		return strings.Contains(code, "#include ") || strings.Contains(code, "int main") || strings.Contains(code, "printf")
	case "cpp":
		return strings.Contains(code, "#include ") || strings.Contains(code, "using namespace") || strings.Contains(code, "std::")
	default:
		return false
	}
}
