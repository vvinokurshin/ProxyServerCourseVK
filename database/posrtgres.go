package database

import (
	"github.com/vvinokurshin/ProxyServerCourseVK/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

var db *gorm.DB

func init() {
	var prodCfgPg = postgres.Config{
		DSN: "host=postgres user=postgres password=postgres port=5432",
	}

	var err error
	db, err = gorm.Open(postgres.New(prodCfgPg), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
}

func InsertRequest(request *models.Request) error {
	tx := db.Model(&models.Request{}).Create(&request)
	if err := tx.Error; err != nil {
		return err
	}

	return nil
}

func InsertResponse(response *models.Response) error {
	tx := db.Model(&models.Response{}).Create(&response)
	if err := tx.Error; err != nil {
		return err
	}

	return nil
}

func SelectRequestByID(requestID uint64) (*models.Request, error) {
	var request *models.Request

	tx := db.Model(&models.Request{}).Where("request_id = ?", requestID).Take(&request)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return request, nil
}

func SelectAllRequests() ([]models.Request, error) {
	var requests []models.Request

	tx := db.Model(&models.Request{}).Find(&requests)
	if err := tx.Error; err != nil {
		return []models.Request{}, err
	}

	return requests, nil
}

func SelectResponseByRequestID(requestID uint64) (*models.Response, error) {
	var response *models.Response

	tx := db.Model(&models.Response{}).Where("request_id = ?", requestID).Take(&response)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return response, nil
}
