package internal

import (
	"database/sql"
	"encoding/json"
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
