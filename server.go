package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb

// var sessionStore *session.Store
var sessionStore memstore.Store

func init() {
	// Register webauthn.SessionData with gob
	gob.Register(webauthn.SessionData{})
}

func main() {

	r := gin.New()

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",                    // Display Name for your site
		RPID:          "localhost",                       // Generally the domain Name for your site
		RPOrigins:     []string{"http://localhost:8080"}, // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	//sessionStore, err = session.NewStore()
	sessionStore = memstore.NewStore([]byte("secret"))
	// memstore.NewStore does not return an error
	/*if err != nil {
		log.Fatal("failed to create session store:", err)
	}*/
	r.Use(sessions.Sessions("fido2-session", sessionStore))

	r.POST("/register/begin", BeginRegistration)
	r.POST("/register/finish", FinishRegistration)
	r.POST("/login/begin", BeginLogin)
	r.POST("/login/finish", FinishLogin)

	r.Static("/static", "./static")
	r.Any("/", Wrap(http.FileServer(http.Dir("./"))))

	if err := r.Run(":8080"); err != nil {
		fmt.Println("Failed to start server")
	}
}

func BeginRegistration(c *gin.Context) {

	// get username/friendly Name
	//username := c.Param("username")

	var user *User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := user.Name

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(user, registerOptions)
	if err != nil {
		log.Println("Error in BeginRegistration:", err)
		//jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// store session data as marshaled JSON
	/*err = sessionStore.SaveWebauthnSession("registration", sessionData, c.Request, c.Writer)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}*/
	session := sessions.Default(c)
	session.Set("sessionData", sessionData)
	err = session.Save()
	if err != nil {
		log.Println("Store sessionData:", err)
		//jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	//jsonResponse(c.Writer, options, http.StatusOK)
	c.JSON(http.StatusOK, options)
}

func FinishRegistration(c *gin.Context) {

	// get username
	var user *User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := user.Name

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		//jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// load the session data
	session := sessions.Default(c)
	sessionData := session.Get("sessionData").(webauthn.SessionData)

	credential, err := webAuthn.FinishRegistration(user, sessionData, c.Request)
	if err != nil {
		log.Println("Error in FinishRegistration:", err.Error())
		//jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	/*parsedResponse, err := protocol.ParseCredentialCreationResponse(c.Request)
	if err != nil {
		log.Println("Error in ParseCredentialCreationResponse:", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	credential, err := webAuthn.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		log.Println("Error in CreateCredential:", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}*/

	user.AddCredential(*credential)

	//jsonResponse(c.Writer, "Registration Success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"status": "registration successful"})
}

func BeginLogin(c *gin.Context) {

	// get username
	//username := c.Param("username")
	var req struct {
		Email string `json:"email"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := req.Email

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		//jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		//jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// store session data as marshaled JSON
	/*err = sessionStore.SaveWebauthnSession("authentication", sessionData, c.Request, c.Writer)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}*/
	session := sessions.Default(c)
	session.Set("sessionData", sessionData)
	err = session.Save()
	if err != nil {
		log.Println("Store sessionData:", err)
		//jsonResponse(c.Writer, err.Error(), http.StatusInternalServerError)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	//jsonResponse(c.Writer, options, http.StatusOK)
	c.JSON(http.StatusOK, options)
}

func FinishLogin(c *gin.Context) {

	// get username
	//username := c.Param("username")
	var req struct {
		Email string `json:"email"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := req.Email

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		//jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// load the session data
	/*sessionData, err := sessionStore.GetWebauthnSession("authentication", c.Request)
	if err != nil {
		log.Println(err)
		jsonResponse(c.Writer, err.Error(), http.StatusBadRequest)
		return
	}*/
	session := sessions.Default(c)
	sessionData := session.Get("sessionData").(webauthn.SessionData)

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the Credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, c.Request)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// handle successful login
	//jsonResponse(c.Writer, "Login Success", http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"status": "login successful"})
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func Wrap(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
