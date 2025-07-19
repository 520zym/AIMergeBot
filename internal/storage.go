package internal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

func NewStorage(dbPath string) *Storage {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("打开sqlite失败: %v", err)
	}
	// 初始化表
	db.Exec(`CREATE TABLE IF NOT EXISTS analyzed_mrs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER,
		mr_iid INTEGER,
		status TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(project_id, mr_iid)
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER,
		mr_iid INTEGER,
		result_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	return &Storage{db: db}
}

// analyzed_mrs相关
func (s *Storage) GetAnalyzedStatus(projectID, mrIID int) (string, error) {
	var status string
	err := s.db.QueryRow("SELECT status FROM analyzed_mrs WHERE project_id=? AND mr_iid=?", projectID, mrIID).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}
func (s *Storage) SetAnalyzedStatus(projectID, mrIID int, status string) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO analyzed_mrs(project_id, mr_iid, status, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", projectID, mrIID, status)
	return err
}

// results相关
func (s *Storage) AddResult(result MRAnalysisResult) error {
	data, _ := json.Marshal(result)
	_, err := s.db.Exec("INSERT INTO results(project_id, mr_iid, result_json) VALUES (?, ?, ?)", result.ProjectID, result.MRID, string(data))
	return err
}
func (s *Storage) GetAllResults() ([]MRAnalysisResult, error) {
	rows, err := s.db.Query("SELECT result_json FROM results")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []MRAnalysisResult
	for rows.Next() {
		var jsonStr string
		if err := rows.Scan(&jsonStr); err == nil {
			var r MRAnalysisResult
			if err := json.Unmarshal([]byte(jsonStr), &r); err == nil {
				results = append(results, r)
			}
		}
	}
	return results, nil
}

func (s *Storage) GetAllProjectsFromResults() ([]Project, error) {
	rows, err := s.db.Query("SELECT result_json FROM results")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projectMap := map[int]Project{}
	for rows.Next() {
		var jsonStr string
		if err := rows.Scan(&jsonStr); err == nil {
			var r MRAnalysisResult
			if err := json.Unmarshal([]byte(jsonStr), &r); err == nil {
				if r.ProjectID != 0 && r.ProjectName != "" {
					projectMap[r.ProjectID] = Project{ID: r.ProjectID, Name: r.ProjectName, Path: r.ProjectPath}
				}
			}
		}
	}
	projects := []Project{}
	for _, p := range projectMap {
		projects = append(projects, p)
	}
	return projects, nil
}

// UpdateReviewStatus 更新指定风险的审核状态
func (s *Storage) UpdateReviewStatus(projectID, mrID, issueIndex int, reviewStatus string) error {
	// 1. 查询 result_json
	row := s.db.QueryRow("SELECT id, result_json FROM results WHERE project_id=? AND mr_iid=?", projectID, mrID)
	var id int
	var jsonStr string
	if err := row.Scan(&id, &jsonStr); err != nil {
		return err
	}
	// 2. 反序列化
	var result MRAnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return err
	}
	// 3. 更新指定 issue 的 review_status
	if issueIndex < 0 || issueIndex >= len(result.Result) {
		return fmt.Errorf("issue_index 越界")
	}
	result.Result[issueIndex].ReviewStatus = reviewStatus
	// 4. 序列化并更新
	newJson, _ := json.Marshal(result)
	_, err := s.db.Exec("UPDATE results SET result_json=? WHERE id=?", string(newJson), id)
	return err
}
