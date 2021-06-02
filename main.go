package main

import (
	"fmt"
	"log"
	"os"
	handler "users/handler"
	pb "users/proto"

	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/jmoiron/sqlx"
	"github.com/micro/micro/v3/service"
	"github.com/micro/micro/v3/service/logger"
)

const schema = `
	create table if not exists users (
		id varchar(36) not null,
		name varchar(125) not null,
		email varchar(225) not null unique,
		password varchar(225) not null,
		surname varchar(125),
		primary key (id)
	);
`

// NewConnection returns a new database connection instance
func NewConnection() (*sqlx.DB, error) {
	host := os.Getenv("DB_HOST")
	user := os.Getenv("DB_USER")
	port := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	password := os.Getenv("DB_PASSWORD")
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+"password=%s dbname=%s sslmode=disable", host, port, user, password, dbName)
	logger.Info("postgres url: ", psqlInfo)
	db, err := sqlx.Connect("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func main() {

	// Creates a database connection and handles
	// closing it again before exit.
	db, err := NewConnection()
	if err != nil {
		log.Panic(err)
	}

	defer db.Close()

	if err != nil {
		log.Fatalf("Could not connect to DB: %v", err)
	}

	// Run schema query on start-up, as we're using "create if not exists"
	// this will only be ran once. In order to create updates, you'll need to
	// use a migrations library
	db.MustExec(schema)

	repo := handler.NewPostgresRepository(db)

	tokenService := &handler.TokenService{
		Repo: repo,
	}

	// Create a new service. Optionally include some options here.
	service := service.New(
		service.Name("users"),
		service.Version("latest"),
	)

	// Init will parse the command line flags.
	//service.Init()
	h := &handler.Handler{
		Repository:   repo,
		TokenService: tokenService,
	}
	// Register handler
	if err := pb.RegisterUsersHandler(service.Server(), h); err != nil {
		log.Panic(err)
	}

	// Run the server
	if err := service.Run(); err != nil {
		log.Panic(err)
	}

}
