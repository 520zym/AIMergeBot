package internal

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string `yaml:"listen"`
	GitLab struct {
		Token string `yaml:"token"`
		URL   string `yaml:"url"`
	} `yaml:"gitlab"`
	OpenAI struct {
		APIKey string `yaml:"api_key"`
		URL    string `yaml:"url"`
		Model  string `yaml:"model"`
	} `yaml:"openai"`
	Projects []struct {
		ID   int    `yaml:"id"`
		Name string `yaml:"name"`
		Path string `yaml:"path"`
	} `yaml:"projects"`
	EnableWebhook       bool     `yaml:"enable_webhook"`
	EnableMRComment     bool     `yaml:"enable_mr_comment"`
	ScanExistingMRs     bool     `yaml:"scan_existing_mrs"`
	EnablePolling       bool     `yaml:"enable_polling"`
	WhitelistExtensions []string `yaml:"whitelist_extensions"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
