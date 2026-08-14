package docs

import "github.com/swaggo/swag"

const docTemplate = `{
  "swagger": "2.0",
  "info": {
    "title": "Ganium API",
    "description": "API documentation for authentication and scam scanning.",
    "version": "1.0.0"
  },
  "host": "localhost:8008",
  "basePath": "/",
  "schemes": ["http"],
  "paths": {}
}`

var SwaggerInfo = &swag.Spec{
	Version:          "1.0.0",
	Host:             "localhost:8008",
	BasePath:         "/",
	Schemes:          []string{"http"},
	Title:            "Ganium API",
	Description:      "API documentation for authentication and scam scanning.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:   docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}

