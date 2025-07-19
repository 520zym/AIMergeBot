package internal

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

type SecurityIssue struct {
	Type          string `json:"type"`
	Desc          string `json:"desc"`
	Code          string `json:"code"`
	Suggestion    string `json:"suggestion"`
	File          string `json:"file"`
	Level         string `json:"level"`
	Context       string `json:"context"`
	FixSuggestion string `json:"fix_suggestion"`
}
