package hander

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	pb "users/proto"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/micro/go-micro/broker"
	"github.com/micro/micro/v3/service/logger"
	"golang.org/x/crypto/bcrypt"
)

var (
	key = []byte("mySuperSecretKey")
)

const topic = "user.created"

type authable interface {
	Decode(token string) (*CustomClaims, error)
	Encode(user *pb.User) (string, error)
}

type Handler struct {
	Repository   Repository
	TokenService authable
	PubSub       broker.Broker
}

type User struct {
	ID       string `sql:"id"`
	Name     string `sql:"name"`
	Email    string `sql:"email"`
	Surname  string `sql:"surname"`
	Password string `sql:"password"`
}

type Repository interface {
	GetAll(ctx context.Context) ([]*User, error)
	Get(ctx context.Context, id string) (*User, error)
	Create(ctx context.Context, user *User) error
	GetByEmail(ctx context.Context, email string) (*User, error)
}

type PostgresRepository struct {
	db *sqlx.DB
}

// CustomClaims is our custom metadata, which will be hashed
// and sent as the second segment in our JWT
type CustomClaims struct {
	User *pb.User
	jwt.StandardClaims
}

type TokenService struct {
	Repo Repository
}

func NewPostgresRepository(db *sqlx.DB) *PostgresRepository {
	return &PostgresRepository{db}
}

func MarshalUserCollection(users []*pb.User) []*User {
	u := make([]*User, len(users))
	for _, val := range users {
		u = append(u, MarshalUser(val))
	}
	return u
}

func MarshalUser(user *pb.User) *User {
	return &User{
		ID:       user.Id,
		Name:     user.Name,
		Email:    user.Email,
		Surname:  user.Surname,
		Password: user.Password,
	}
}

func UnmarshalUserCollection(users []*User) []*pb.User {
	u := make([]*pb.User, len(users))
	for _, val := range users {
		u = append(u, UnmarshalUser(val))
	}
	return u
}

func UnmarshalUser(user *User) *pb.User {
	return &pb.User{
		Id:       user.ID,
		Name:     user.Name,
		Email:    user.Email,
		Surname:  user.Surname,
		Password: user.Password,
	}
}

func (r *PostgresRepository) GetAll(ctx context.Context) ([]*User, error) {
	users := make([]*User, 0)
	query := `select * from users;`
	rows, err := r.db.Query(query)
	if err != nil {
		logger.Info("Error query", err)
	}
	defer rows.Close()
	for rows.Next() {
		var user User
		err = rows.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Surname)
		if err != nil {
			logger.Error(err)
		}
		users = append(users, &user)
	}
	/*if err := r.db.GetContext(ctx, users, "select * from users"); err != nil {
		return users, err
	}*/
	err = rows.Err()
	if err != nil {
		logger.Error(err)
	}
	return users, nil
}

func (r *PostgresRepository) Get(ctx context.Context, id string) (*User, error) {
	query := `select * from users where id = $1;`
	var user User
	var poi *User
	row := r.db.QueryRow(query, id)
	err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Surname)
	if err != nil {
		logger.Info("Error select ", err)
	}
	poi = &user
	return poi, nil
}

// Create a new user
func (r *PostgresRepository) Create(ctx context.Context, user *User) error {
	u, err := uuid.NewV4()
	user.ID = u.String()
	log.Println(user)
	query := "insert into users (id, name, email, surname, password) values ($1, $2, $3, $4, $5)"
	_, err = r.db.ExecContext(ctx, query, user.ID, user.Name, user.Email, user.Surname, user.Password)
	return err
}

// GetByEmail fetches a single user by their email address
func (r *PostgresRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `select * from users where email=$1;`
	var user User
	var poi *User
	row := r.db.QueryRow(query, email)
	err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Surname)
	if err != nil {
		logger.Info("Error select ", err)
	}
	poi = &user
	return poi, nil
}

// Decode a token string into a token object
func (srv *TokenService) Decode(token string) (*CustomClaims, error) {

	// Parse the token
	tokenType, err := jwt.ParseWithClaims(token, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	// Validate the token and return the custom claims
	if claims, ok := tokenType.Claims.(*CustomClaims); ok && tokenType.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

// Encode a claim into a JWT
func (srv *TokenService) Encode(user *pb.User) (string, error) {
	// Create the Claims
	claims := CustomClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: 15000,
			Issuer:    "users",
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token and return
	return token.SignedString(key)
}

func (s *Handler) Get(ctx context.Context, req *pb.User, res *pb.Response) error {
	result, err := s.Repository.Get(ctx, req.Id)
	if err != nil {
		return err
	}

	user := UnmarshalUser(result)
	res.User = user

	return nil
}

func (s *Handler) GetAll(ctx context.Context, req *pb.Request, res *pb.Response) error {
	results, err := s.Repository.GetAll(ctx)
	if err != nil {
		return err
	}

	users := UnmarshalUserCollection(results)
	res.Users = users

	return nil
}

func (s *Handler) Auth(ctx context.Context, req *pb.User, res *pb.Token) error {
	user, err := s.Repository.GetByEmail(ctx, req.Email)
	if err != nil {
		return err
	}
	logger.Info("Hash password = ", user.Password)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return err
	}
	tok := UnmarshalUser(user)
	token, err := s.TokenService.Encode(tok)
	if err != nil {
		return err
	}

	res.Token = token
	return nil
}

func (s *Handler) Create(ctx context.Context, req *pb.User, res *pb.Response) error {
	log.Println("user:", req)
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	req.Password = string(hashedPass)
	if err := s.Repository.Create(ctx, MarshalUser(req)); err != nil {
		return err
	}
	if err := s.publishEvent(req); err != nil {
		return err
	}

	return nil
	// Strip the password back out, so's we're not returning it
	req.Password = ""
	res.User = req

	return nil
}

func (s *Handler) ValidateToken(ctx context.Context, req *pb.Token, res *pb.Token) error {
	claims, err := s.TokenService.Decode(req.Token)
	if err != nil {
		return err
	}

	if claims.User.Id == "" {
		return errors.New("invalid user")
	}

	res.Valid = true
	return nil
}

func (srv *Handler) publishEvent(user *pb.User) error {
	// Marshal to JSON string
	body, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// Create a broker message
	msg := &broker.Message{
		Header: map[string]string{
			"id": user.Id,
		},
		Body: body,
	}

	// Publish message to broker
	if err := srv.PubSub.Publish(topic, msg); err != nil {
		log.Printf("[pub] failed: %v", err)
	}

	return nil
}
