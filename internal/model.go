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
	ID   int    `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
	Path string `yaml:"path" json:"path"`
}

// FlexibleString 兼容 string 或 []string 的 JSON 反序列化
type FlexibleString string

func (f *FlexibleString) UnmarshalJSON(data []byte) error {
	// 尝试解析为字符串
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = FlexibleString(s)
		return nil
	}
	// 尝试解析为字符串数组
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = FlexibleString(strings.Join(arr, "\n"))
		return nil
	}
	return json.Unmarshal(data, (*string)(f)) // fallback
}

type SecurityIssue struct {
	Type          string         `json:"type"`
	Desc          string         `json:"desc"`
	Code          FlexibleString `json:"code"`
	Suggestion    string         `json:"suggestion"`
	File          string         `json:"file"`
	Level         string         `json:"level"`
	Context       string         `json:"context"`
	FixSuggestion string         `json:"fix_suggestion"`
}
