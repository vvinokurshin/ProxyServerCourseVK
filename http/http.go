package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vvinokurshin/ProxyServerCourseVK/database"
	"github.com/vvinokurshin/ProxyServerCourseVK/models"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	ContentTypeJSON       = "application/json"
	ContentTypeUrlencoded = "application/x-www-form-urlencoded"
)

func ProxyHttps(w http.ResponseWriter, r *http.Request) error {
	// TODO
	panic("not implemented")
}

func ParseRequest(r *http.Request) *models.Request {
	queryBytes, _ := json.Marshal(r.URL.Query())
	queryRaw := json.RawMessage(queryBytes)
	headersBytes, _ := json.Marshal(r.Header)
	headersRaw := json.RawMessage(headersBytes)
	cookiesBytes, _ := json.Marshal(r.Cookies())
	cookiesRaw := json.RawMessage(cookiesBytes)

	parsedRequest := &models.Request{
		Method:      r.Method,
		Path:        fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path),
		QueryParams: &queryRaw,
		Headers:     &headersRaw,
		Cookies:     &cookiesRaw,
		ContentType: r.Header.Get("Content-Type"),
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil
	}

	parsedRequest.Body = string(body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return parsedRequest
}

func ParseResponse(resp *http.Response) *models.Response {
	headersBytes, _ := json.Marshal(resp.Header)
	headersRaw := json.RawMessage(headersBytes)

	parsedResponse := &models.Response{
		StatusCode:  resp.StatusCode,
		Message:     resp.Status,
		Headers:     &headersRaw,
		ContentType: resp.Header.Get("Content-Type"),
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	parsedResponse.Body = string(body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return parsedResponse
}

func ProxyHttp(w http.ResponseWriter, r *http.Request) error {
	request := ParseRequest(r)
	err := database.InsertRequest(request)
	if err != nil {
		return err
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return nil
	}
	r.Header.Del("Proxy-Connection")
	r = fixRequest(r)

	response := ParseResponse(resp)
	response.RequestID = request.RequestID

	defer resp.Body.Close()
	CopyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	err = database.InsertResponse(response)
	if err != nil {
		return err
	}

	return nil
}

func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func fixRequest(r *http.Request) *http.Request {
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.RequestURI = ""
	return r
}

func CreateRequest(request *models.Request) (*http.Request, error) {
	r, err := http.NewRequest(request.Method, request.Path, nil)
	if err != nil {
		return nil, err
	}

	var queryParams map[string]interface{}
	err = json.Unmarshal(*request.QueryParams, &queryParams)
	if err != nil {
		return nil, err
	}

	values := url.Values{}

	for key, value := range queryParams {
		switch v := value.(type) {
		case []interface{}:
			for _, val := range v {
				values.Add(key, fmt.Sprint(val))
			}
		default:
			values.Add(key, fmt.Sprint(value))
		}
	}

	r.URL.RawQuery = values.Encode()

	if request.Headers != nil {
		headers := http.Header{}
		if err := json.Unmarshal(*request.Headers, &headers); err != nil {
			return nil, err
		}
		r.Header = headers
	}

	if request.Cookies != nil {
		var cookies []*http.Cookie
		if err := json.Unmarshal(*request.Cookies, &cookies); err != nil {
			return nil, err
		}
		for _, cookie := range cookies {
			if !reqContainsCookie(r, cookie) {
				r.AddCookie(cookie)
			}
		}
	}

	r.Header.Set("Content-Type", request.ContentType)
	if request.Body != "" {
		r.Body = ioutil.NopCloser(strings.NewReader(request.Body))
		r.ContentLength = int64(len(request.Body))
	}

	return r, nil
}

func RepeatRequest(request *models.Request) (*http.Response, error) {
	r, err := CreateRequest(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func reqContainsCookie(req *http.Request, cookie *http.Cookie) bool {
	cookies := req.Cookies()
	for _, c := range cookies {
		if c.Name == cookie.Name && c.Value == cookie.Value {
			return true
		}
	}
	return false
}

func getContentLength(headers *json.RawMessage) int {
	if headers == nil {
		return 0
	}

	var m map[string]string
	if err := json.Unmarshal(*headers, &m); err != nil {
		return 0
	}

	contentLength, _ := strconv.Atoi(m["Content-Length"])
	return contentLength
}

func cmpResponses(r *http.Request, response *models.Response) (bool, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	newResponse := ParseResponse(resp)

	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	return newResponse.StatusCode == response.StatusCode && newResponse.Message == response.Message &&
		newResponse.ContentType == response.ContentType && getContentLength(response.Headers) == getContentLength(newResponse.Headers), nil
}

func checkQueryParams(r *http.Request, response *models.Response) error {
	query := r.URL.Query()

	for key, values := range query {
		query.Del(key)
		for _, value := range values {
			query.Add(key, value+"'")
		}
		r.URL.RawQuery = query.Encode()

		isEqual, err := cmpResponses(r, response)
		if err != nil {
			return err
		}
		if isEqual == false {
			return errors.New(fmt.Sprintf("query parameter '%s' is vulnerable", key))
		}

		query.Del(key)
		for _, value := range values {
			query.Add(key, value+"\"")
		}
		r.URL.RawQuery = query.Encode()

		isEqual, err = cmpResponses(r, response)
		if err != nil {
			return err
		}
		if isEqual == false {
			return errors.New(fmt.Sprintf("query parameter '%s' is vulnerable", key))
		}

		query.Del(key)
		for _, value := range values {
			query.Add(key, value)
		}
		r.URL.RawQuery = query.Encode()
	}

	return nil
}

func checkJsonBody(r *http.Request, response *models.Response) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var requestBodyMap map[string]interface{}
	err = json.Unmarshal(body, &requestBodyMap)
	if err != nil {
		return err
	}

	for key, value := range requestBodyMap {
		if strValue, ok := value.(string); ok {
			requestBodyMap[key] = strValue + "'"
			modifiedRequestBody, err := json.Marshal(requestBodyMap)
			if err != nil {
				return err
			}

			r.Body = ioutil.NopCloser(bytes.NewBuffer(modifiedRequestBody))
			r.ContentLength = int64(len(modifiedRequestBody))
			isEqual, err := cmpResponses(r, response)
			if err != nil {
				return err
			}
			if isEqual == false {
				return errors.New(fmt.Sprintf("parameter '%s' in json data is vulnerable", key))
			}

			requestBodyMap[key] = strValue + "\""
			modifiedRequestBody, err = json.Marshal(requestBodyMap)
			if err != nil {
				return err
			}

			r.Body = ioutil.NopCloser(bytes.NewBuffer(modifiedRequestBody))
			r.ContentLength = int64(len(modifiedRequestBody))
			isEqual, err = cmpResponses(r, response)
			if err != nil {
				return err
			}
			if isEqual == false {
				return errors.New(fmt.Sprintf("parameter '%s' in json data is vulnerable", key))
			}

			requestBodyMap[key] = strValue
		}
	}

	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	r.ContentLength = int64(len(body))

	return nil
}

func checkUrlEncodedBody(r *http.Request, response *models.Response) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	bodyStr := string(body)

	parameters, err := url.ParseQuery(bodyStr)
	if err != nil {
		return err
	}

	for key, values := range parameters {
		original := make([]string, len(values))
		copy(original, values)

		for i, value := range original {
			parameters[key][i] = value + "'"
		}

		newBody := []byte(parameters.Encode())
		r.Body = ioutil.NopCloser(bytes.NewBuffer(newBody))
		r.ContentLength = int64(len(newBody))

		isEqual, err := cmpResponses(r, response)
		if err != nil {
			return err
		}
		if isEqual == false {
			return errors.New(fmt.Sprintf("parameter '%s' in json data is vulnerable", key))
		}

		for i, value := range original {
			parameters[key][i] = value + "\""
		}

		newBody = []byte(parameters.Encode())
		r.Body = ioutil.NopCloser(bytes.NewBuffer(newBody))
		r.ContentLength = int64(len(newBody))

		isEqual, err = cmpResponses(r, response)
		if err != nil {
			return err
		}
		if isEqual == false {
			return errors.New(fmt.Sprintf("parameter '%s' in urlencoded data is vulnerable", key))
		}

		for i, value := range original {
			parameters[key][i] = value
		}
	}

	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	r.ContentLength = int64(len(body))

	return nil
}

func checkCookiesBody(r *http.Request, response *models.Response) error {
	for _, cookie := range r.Cookies() {
		cookie.Value = cookie.Value + "'"
		r.AddCookie(cookie)
	}

	isEqual, err := cmpResponses(r, response)
	if err != nil {
		return err
	}
	if isEqual == false {
		return errors.New("cookies are vulnerable")
	}

	return nil
}

func ScanRequest(request *models.Request, response *models.Response) error {
	r, err := CreateRequest(request)
	if err != nil {
		return nil
	}

	err = checkQueryParams(r, response)
	if err != nil {
		return err
	}

	if r.Header.Get("Content-Type") == ContentTypeJSON {
		err = checkJsonBody(r, response)
		if err != nil {
			return err
		}
	} else if r.Header.Get("Content-Type") == ContentTypeUrlencoded {
		err = checkUrlEncodedBody(r, response)
		if err != nil {
			return err
		}
	}

	err = checkCookiesBody(r, response)
	if err != nil {
		return err
	}

	return nil
}
