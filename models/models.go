package models

import (
	"encoding/json"
)

type Request struct {
	RequestID   uint64           `json:"request_id" gorm:"primaryKey"`
	Method      string           `json:"method"`
	Path        string           `json:"path"`
	QueryParams *json.RawMessage `json:"query_params" gorm:"type:jsonb"`
	Headers     *json.RawMessage `json:"headers" gorm:"type:jsonb"`
	Cookies     *json.RawMessage `json:"cookies" gorm:"type:jsonb"`
	ContentType string           `json:"content_type"`
	Body        string           `json:"body"`
}

type Response struct {
	ResponseID  uint64 `gorm:"primaryKey"`
	StatusCode  int
	Message     string
	Headers     *json.RawMessage `gorm:"type:jsonb"`
	ContentType string
	Body        string
	RequestID   uint64
}

type Error struct {
	Error string `json:"error"`
}

type ReqsResponse struct {
	Requests []Request `json:"requests"`
	Count    int       `json:"count"`
}

type ReqResponse struct {
	Request Request `json:"request"`
}

type ScanResponse struct {
	Result string `json:"result"`
	What   string `json:"what"`
}
