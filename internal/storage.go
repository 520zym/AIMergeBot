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
	// 初始化表，始终包含review_status字段
	db.Exec(`CREATE TABLE IF NOT EXISTS analyzed_mrs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER,
		mr_iid INTEGER,
		status TEXT,
		review_status TEXT DEFAULT 'pending',
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
	
	// 新增ReAct审计结果表
	db.Exec(`CREATE TABLE IF NOT EXISTS react_audit_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER,
		mr_iid INTEGER,
		react_result_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(project_id, mr_iid)
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

// 设置审核状态（MR维度）
func (s *Storage) SetReviewStatus(projectID, mrIID int, reviewStatus string) error {
	log.Printf("SetReviewStatus: project_id=%d, mr_id=%d, review_status=%s", projectID, mrIID, reviewStatus)
	res, err := s.db.Exec("UPDATE analyzed_mrs SET review_status=?, updated_at=CURRENT_TIMESTAMP WHERE project_id=? AND mr_iid=?", reviewStatus, projectID, mrIID)
	if err != nil {
		log.Printf("SetReviewStatus UPDATE error: %v", err)
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		// 插入新行，status默认pending
		_, err = s.db.Exec("INSERT INTO analyzed_mrs(project_id, mr_iid, status, review_status, updated_at) VALUES (?, ?, 'pending', ?, CURRENT_TIMESTAMP)", projectID, mrIID, reviewStatus)
		if err != nil {
			log.Printf("SetReviewStatus INSERT error: %v", err)
		}
	}
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

// 获取审核状态（MR维度）
func (s *Storage) GetReviewStatus(projectID, mrIID int) (string, error) {
	var reviewStatus string
	err := s.db.QueryRow("SELECT review_status FROM analyzed_mrs WHERE project_id=? AND mr_iid=?", projectID, mrIID).Scan(&reviewStatus)
	if err == sql.ErrNoRows {
		return "pending", nil
	}
	return reviewStatus, err
}

// ReAct审计结果相关方法
func (s *Storage) SaveReActAuditResult(projectID, mrIID int, result *ReActAuditResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("序列化ReAct结果失败: %v", err)
	}
	
	_, err = s.db.Exec("INSERT OR REPLACE INTO react_audit_results(project_id, mr_iid, react_result_json, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", 
		projectID, mrIID, string(data))
	return err
}

func (s *Storage) GetReActAuditResult(projectID, mrIID int) (*ReActAuditResult, error) {
	var jsonStr string
	err := s.db.QueryRow("SELECT react_result_json FROM react_audit_results WHERE project_id=? AND mr_iid=?", projectID, mrIID).Scan(&jsonStr)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("未找到ReAct审计结果")
	}
	if err != nil {
		return nil, fmt.Errorf("查询ReAct审计结果失败: %v", err)
	}
	
	var result ReActAuditResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("反序列化ReAct结果失败: %v", err)
	}
	
	return &result, nil
}
