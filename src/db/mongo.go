package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const DatabaseURL = `mongodb://localhost:27017`
const DatabaseName = "ganium"
const CollectionName = "ganium"

var MongoClient *mongo.Client

func ConnectMongoDB() error {
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