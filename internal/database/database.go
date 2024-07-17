package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/andresaclan/passkey/internal/user"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/joho/godotenv/autoload"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

func New() *sql.DB {
	dbURL := os.Getenv("TURSO_DATABASE")
	dbAuthToken := os.Getenv("TURSO_AUTH_TOKEN")

	url := fmt.Sprintf("libsql://%s.turso.io?authToken=%s", dbURL, dbAuthToken)

	db, err := sql.Open("libsql", url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open db %s: %s", url, err)
		os.Exit(1)
	}
	// queryUsers(db)

	// drop tables
	db.Exec(`DROP TABLE sessions;`)
	db.Exec(`DROP TABLE users;`)
	//create tables if they dont exist
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id BLOB PRIMARY KEY,
		display_name TEXT NOT NULL,
		name TEXT NOT NULL,
		creds BLOB
	);`)

	db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id BLOB NOT NULL UNIQUE,
		session_data BLOB,
		FOREIGN KEY (user_id) REFERENCES users (id)
	);`)
	return db
}

// gets user from db
func GetUser(db *sql.DB, username string) (user.User, error) {
	row := db.QueryRow("SELECT * FROM users WHERE name=?", username)

	var u user.User
	var credsData []byte
	if err := row.Scan(&u.ID, &u.DisplayName, &u.Name, &credsData); err != nil {
		// user doesnt exists
		return user.User{}, err
	}

	if err := u.UnmarshalCreds(credsData); err != nil {
		return user.User{}, err
	}

	return u, nil
}

func GetUserFromSessionUserID(db *sql.DB, userID []byte) (user.User, error) {
	query := `
	SELECT users.id, users.display_name, users.name, users.creds
	FROM users
	JOIN sessions ON users.id = sessions.user_id
	WHERE sessions.user_id = ?`

	row := db.QueryRow(query, userID)

	var u user.User
	var credsData []byte
	err := row.Scan(&u.ID, &u.DisplayName, &u.Name, &credsData)
	if err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, fmt.Errorf("user not found")
		}
		return user.User{}, err
	}
	if len(credsData) == 0 {
		return u, nil
	}
	if err := u.UnmarshalCreds(credsData); err != nil {
		return user.User{}, err
	}
	return u, nil
}

func CreateUser(db *sql.DB, username string) (user.User, error) {
	query := `INSERT INTO users (id, display_name, name) VALUES (?, ?, ?)`

	// create user struct
	newUser := user.User{
		ID:          []byte(username),
		DisplayName: username,
		Name:        username,
	}

	_, err := db.Exec(query, newUser.WebAuthnID(), newUser.WebAuthnDisplayName(), newUser.WebAuthnName())
	if err != nil {
		return newUser, err
	}
	return newUser, nil
}

// Saves updated user to Database (ex. if any credentials were updated we need to save that)
func SaveUser(db *sql.DB, u user.User) error {
	fmt.Println("Saving User", u.DisplayName)
	query := `UPDATE users SET creds = ? WHERE id = ?`
	fmt.Println("len of creds for user", len(u.WebAuthnCredentials()))
	// Execute the update statement
	credentialsJSON, err := json.Marshal(u.WebAuthnCredentials())
	if err != nil {
		return err
	}

	_, err = db.Exec(query, credentialsJSON, u.WebAuthnID())
	return err

}
func GetSession(db *sql.DB, token string) (webauthn.SessionData, bool, error) {
	query := `SELECT session_data FROM sessions WHERE token = ?`

	var sessionDataBlob []byte
	err := db.QueryRow(query, token).Scan(&sessionDataBlob)
	if err != nil {
		if err == sql.ErrNoRows {
			return webauthn.SessionData{}, false, nil
		}
		return webauthn.SessionData{}, false, err
	}

	var sessionData webauthn.SessionData
	err = json.Unmarshal(sessionDataBlob, &sessionData)
	if err != nil {
		return webauthn.SessionData{}, false, err
	}

	return sessionData, true, nil
}

func SaveSession(db *sql.DB, token string, data webauthn.SessionData) {
	query := `
	INSERT OR REPLACE INTO sessions (token, user_id, session_data)
	VALUES (?, ?, ?)
	`
	sessionDataJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("failed to serialize sessionData before saving to database")
		return
	}
	userID := data.UserID
	_, err = db.Exec(query, token, userID, sessionDataJSON)
	if err != nil {
		fmt.Println("failed to save session to database", err)
	}
}

func DeleteSession(db *sql.DB, token string) error {
	query := `DELETE FROM sessions WHERE token = ?`

	_, err := db.Exec(query, token)
	return err
}

func GenSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil

}

// // TODO update this function
// func queryUsers(db *sql.DB) {
// 	rows, err := db.Query("SELECT * FROM users")
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "failed to execute query: %v\n", err)
// 		os.Exit(1)
// 	}
// 	defer rows.Close()

// 	// var users []User

// 	for rows.Next() {
// 		var user user.User

// 		if err := rows.Scan(&user.ID, &user.Name); err != nil {
// 			fmt.Println("Error scanning row:", err)
// 			return
// 		}

// 		// users = append(users, user)
// 		fmt.Println(user.ID, user.Name)
// 	}

// 	if err := rows.Err(); err != nil {
// 		fmt.Println("Error during rows iteration:", err)
// 	}
// }
