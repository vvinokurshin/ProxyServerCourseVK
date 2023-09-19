package pkg

import (
	"encoding/json"
	myhttp "github.com/vvinokurshin/ProxyServerCourseVK/http"
	"net/http"
)

type ResponseWriterCode struct {
	http.ResponseWriter
	StatusCode int
}

func NewResponseWriterCode(w http.ResponseWriter) *ResponseWriterCode {
	return &ResponseWriterCode{w, http.StatusOK}
}

func (rw *ResponseWriterCode) WriteHeader(code int) {
	rw.StatusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func SendJSON(w http.ResponseWriter, status int, dataStruct any) {
	dataJSON, err := json.Marshal(dataStruct)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", myhttp.ContentTypeJSON)
	w.WriteHeader(status)

	_, err = w.Write(dataJSON)
	if err != nil {
		return
	}
}
