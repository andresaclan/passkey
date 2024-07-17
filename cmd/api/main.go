package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"database/sql"

	"github.com/andresaclan/passkey/internal/database"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err      error
	db       *sql.DB
)

func main() {
	// serve web files
	http.Handle("/", http.FileServer(http.Dir("./web")))

	// initialize database connection
	db = database.New()

	// initialize webauthn
	wconfig := &webauthn.Config{
		RPDisplayName: "Passkey",                         // Display Name for your site
		RPID:          "localhost",                       // Generally the FQDN for your site
		RPOrigins:     []string{"http://localhost:8080"}, // The origin URLs allowed for WebAuthn requests
	}

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Println(err)
	}

	// add http routes
	http.HandleFunc("/api/passkey/registerStart", BeginRegistration)
	http.HandleFunc("/api/passkey/registerFinish", FinishRegistration)
	http.HandleFunc("/api/passkey/loginStart", BeginLogin)
	http.HandleFunc("/api/passkey/loginFinish", FinishLogin)

	// start server
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	username, err := getUsername(r)
	if err != nil {
		// TODO handle error
		fmt.Println("could not get username from request body", err)
		panic(err)
	}
	u, err := database.CreateUser(db, username)
	if err != nil {
		msg := "failed to create user. User may already exist"
		fmt.Println(msg, err.Error())
		JSONResponse(w, msg, http.StatusConflict)
		return
	}

	options, session, err := webAuthn.BeginRegistration(u)

	if err != nil {
		msg := fmt.Sprintf("can't begin registration: %s", err.Error())
		fmt.Printf("[ERRO] %s\n", msg)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	t, err := database.GenSessionID()
	if err != nil {
		fmt.Printf("[ERRO] can't generate session id: %s\n", err.Error())

		panic(err) // FIXME: handle error
	}

	database.SaveSession(db, t, *session)

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "api/passkey/registerStart",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	JSONResponse(w, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options

}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	fmt.Println("start of FinishRegistration()")
	sid, err := r.Cookie("sid")
	if err != nil {
		fmt.Printf("[ERRO] can't get session id: %s\n", err.Error())

		panic(err) // FIXME: handle error
	}

	session, _, err := database.GetSession(db, sid.Value)
	if err != nil {
		fmt.Println("error getting session")
		panic(err)
	}

	user, err := database.GetUserFromSessionUserID(db, session.UserID)
	if err != nil {
		fmt.Println("could not get user from sessionUserID")
		panic(err)
	}

	credential, err := webAuthn.FinishRegistration(user, session, r)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		fmt.Printf("[ERRO] %s\n", msg)
		// clean up sid cookie
		http.SetCookie(w, &http.Cookie{
			Name:  "sid",
			Value: "",
		})
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	user.AddCredential(credential)
	err = database.SaveUser(db, user)
	if err != nil {
		panic(err)
	}

	// Delete the session data
	err = database.DeleteSession(db, sid.Value)
	if err != nil {
		fmt.Println("failed to delete session from databse")
		panic(err)
	}
	// delete session token from cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

	fmt.Println("end of FinishRegistration()")
	JSONResponse(w, "Registration Success", http.StatusOK)

}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("start of BeginLogin()")
	username, err := getUsername(r)
	if err != nil {
		// TODO handle error
		fmt.Println("could not get username from request body", err)
		panic(err)
	}

	user, err := database.GetUser(db, username)
	if err != nil {
		msg := "failed to get user. User may not exist"
		fmt.Println(msg, err.Error())
		JSONResponse(w, msg, http.StatusConflict)
		return
	}

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		fmt.Printf("[ERRO] %s\n", msg)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	t, err := database.GenSessionID()
	if err != nil {
		fmt.Printf("[ERRO] can't generate session id: %s\n", err.Error())

		panic(err) // FIXME: handle error
	}

	database.SaveSession(db, t, *session)

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "api/passkey/registerStart",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	fmt.Println("end of BeginLogin()")
	JSONResponse(w, options, http.StatusOK) // return the options generated with the session key
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	sid, err := r.Cookie("sid")
	if err != nil {
		fmt.Printf("[ERRO] can't get session id: %s\n", err.Error())

		panic(err) // FIXME: handle error
	}

	session, _, err := database.GetSession(db, sid.Value)
	if err != nil {
		fmt.Println("error getting session")
		panic(err)
	}

	user, err := database.GetUserFromSessionUserID(db, session.UserID)
	if err != nil {
		fmt.Println("could not get user from sessionUserID")
		panic(err)
	}

	credential, err := webAuthn.FinishLogin(user, session, r)
	if err != nil {
		fmt.Printf("[ERRO] can't finish login: %s\n", err.Error())
		panic(err)
	}

	if credential.Authenticator.CloneWarning {
		fmt.Printf("[WARN] can't finish login: %s", "CloneWarning")
	}

	// If login was successful, update the credential object
	user.UpdateCredential(credential)
	database.SaveUser(db, user)

	// Delete the login session data
	database.DeleteSession(db, sid.Value)
	http.SetCookie(w, &http.Cookie{
		Name:  "sid",
		Value: "",
	})

	// Add the new session cookie
	t, err := database.GenSessionID()
	if err != nil {
		fmt.Printf("[ERRO] can't generate session id: %s\n", err.Error())

		panic(err) // TODO: handle error
	}

	database.SaveSession(db, t, webauthn.SessionData{
		UserID:  user.WebAuthnID(),
		Expires: time.Now().Add(time.Hour),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	fmt.Printf("[INFO] finish login ----------------------/\n")
	JSONResponse(w, "Login Success", http.StatusOK)
}

// gets username from the request body
func getUsername(r *http.Request) (string, error) {
	type Username struct {
		Username string `json:"username"`
	}
	var u Username
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return "", err
	}

	return u.Username, nil

}

func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
