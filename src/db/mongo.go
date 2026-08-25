package db

import (
	"context"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var DatabaseURL = `mongodb://localhost:27017`
var DatabaseName = "ganium"

const CollectionName = "ganium"

var MongoClient *mongo.Client

func ConnectMongoDB() error {
	if uri := strings.TrimSpace(os.Getenv("MONGO_URI")); uri != "" {
		DatabaseURL = uri
	}
	if dbName := strings.TrimSpace(os.Getenv("MONGO_DATABASE")); dbName != "" {
		DatabaseName = dbName
	}

	client, err := mongo.Connect(options.Client().ApplyURI(DatabaseURL))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Ping(ctx, nil)
	if err != nil {
		return err
	}

	MongoClient = client

	return nil
}

func CreateCollection(arg string) error {
	err := MongoClient.Database(DatabaseName).CreateCollection(
		context.Background(),
		arg,
	)
	return err
}
