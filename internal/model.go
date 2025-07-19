package internal

import (
	"encoding/json"
	"strings"
)

type GitLab struct {
	Token string `yaml:"token"`
	URL   string `yaml:"url"`
}

type OpenAI struct {
	APIKey string `yaml:"api_key"`
	URL    string `yaml:"url"`
	Model  string `yaml:"model"`
}

type Project struct {
	ID   int    `yaml:"id"`
	Name string `yaml:"name"`
}

type SecurityIssue struct {
	Type          string `json:"type"`
	Desc          string `json:"desc"`
	Code          string `json:"code"`
	Suggestion    string `json:"suggestion"`
	File          string `json:"file"`
	Level         string `json:"level"`          // high/medium/low
	Context       string `json:"context"`        // 相关上下文
	FixSuggestion string `json:"fix_suggestion"` // AI生成的修复代码
}

func (s *SecurityIssue) UnmarshalJSON(data []byte) error {
	type Alias SecurityIssue
	tmp := &struct {
		Code interface{} `json:"code"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	s.Type = tmp.Type
	s.Desc = tmp.Desc
	s.Suggestion = tmp.Suggestion
	s.File = tmp.File
	s.Level = tmp.Level
	s.Context = tmp.Context
	// 兼容 code 为 string 或 []string
	switch v := tmp.Code.(type) {
	case string:
		s.Code = v
	case []interface{}:
		var lines []string
		for _, line := range v {
			if str, ok := line.(string); ok {
				lines = append(lines, str)
			}
		}
		s.Code = strings.Join(lines, "\n")
	}
	return nil
}

type MRAnalysisResult struct {
	MRID          int             `json:"mr_id"`
	ProjectID     int             `json:"project_id"`
	ProjectName   string          `json:"project_name"`
	ProjectPath   string          `json:"project_path"`
	MRTitle       string          `json:"mr_title"`
	MRAuthor      string          `json:"mr_author"`
	MRCreated     string          `json:"mr_created"`
	MRBranch      string          `json:"mr_branch"`
	MRDesc        string          `json:"mr_desc"`
	MRUrl         string          `json:"mr_url"`
	GitLabBaseUrl string          `json:"gitlab_base_url"`
	Result        []SecurityIssue `json:"result"`
}
