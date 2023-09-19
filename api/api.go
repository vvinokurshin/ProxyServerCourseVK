package api

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/vvinokurshin/ProxyServerCourseVK/database"
	myhttp "github.com/vvinokurshin/ProxyServerCourseVK/http"
	"github.com/vvinokurshin/ProxyServerCourseVK/models"
	"github.com/vvinokurshin/ProxyServerCourseVK/pkg"
	"io"
	"net/http"
	"strconv"
)

func AddRoutes(r *mux.Router) {
	r.HandleFunc("/requests", GetAllRequests).Methods(http.MethodGet)
	r.HandleFunc("/requests/{id}", GetRequest).Methods(http.MethodGet)
	r.HandleFunc("/repeat/{id}", RepeatRequest).Methods(http.MethodGet)
	r.HandleFunc("/scan/{id}", ScanRequest).Methods(http.MethodGet)
}

func GetAllRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := database.SelectAllRequests()
	if err != nil {
		pkg.SendJSON(w, http.StatusInternalServerError, models.Error{
			Error: err.Error(),
		})
		return
	}

	pkg.SendJSON(w, http.StatusOK, models.ReqsResponse{
		Requests: requests,
		Count:    len(requests),
	})
}

func GetRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		pkg.SendJSON(w, http.StatusBadRequest, models.Error{
			Error: err.Error(),
		})
		return
	}

	request, err := database.SelectRequestByID(requestID)
	if err != nil {
		pkg.SendJSON(w, http.StatusInternalServerError, models.Error{
			Error: err.Error(),
		})
		return
	}

	pkg.SendJSON(w, http.StatusOK, models.ReqResponse{
		Request: *request,
	})
}

func RepeatRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		pkg.SendJSON(w, http.StatusBadRequest, models.Error{
			Error: err.Error(),
		})
		return
	}

	request, err := database.SelectRequestByID(requestID)
	if err != nil {
		pkg.SendJSON(w, http.StatusInternalServerError, models.Error{
			Error: err.Error(),
		})
		return
	}

	response, err := myhttp.RepeatRequest(request)
	if err != nil {
		fmt.Println(err)
		pkg.SendJSON(w, http.StatusInternalServerError, models.Error{
			Error: err.Error(),
		})
		return
	}

	defer response.Body.Close()
	myhttp.CopyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

func ScanRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		pkg.SendJSON(w, http.StatusBadRequest, models.Error{
			Error: err.Error(),
		})
		return
	}

	request, err := database.SelectRequestByID(requestID)
	if err != nil {
		pkg.SendJSON(w, http.StatusInternalServerError, models.Error{
			Error: err.Error(),
		})
		return
	}

	response, err := database.SelectResponseByRequestID(requestID)
	if err != nil {
		pkg.SendJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	
	err = myhttp.ScanRequest(request, response)
	if err != nil {
		pkg.SendJSON(w, http.StatusInternalServerError, models.ScanResponse{
			Result: "FAIL",
			What:   err.Error(),
		})
	}

	pkg.SendJSON(w, http.StatusOK, models.ScanResponse{
		Result: "SUCCESS",
	})
}
