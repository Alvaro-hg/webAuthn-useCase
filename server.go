package main

import (
	"encoding/gob"
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

var sessionStore memstore.Store

func init() {
	gob.Register(webauthn.SessionData{})
}

func main() {

	r := gin.New()

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",                    // Display Name for your site
		RPID:          "localhost",                       // Generally the domain Name for your site
		RPOrigins:     []string{"http://localhost:8080"}, // The origin URLs for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore = memstore.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("fido2-session", sessionStore))

	r.GET("/register/begin/:email", BeginRegistration)
	r.POST("/register/finish/:email", FinishRegistration)
	r.GET("/login/begin/:email", BeginLogin)
	r.POST("/login/finish/:email", FinishLogin)

	r.Any("/", Wrap(http.FileServer(http.Dir("./"))))

	if err := r.Run(":8080"); err != nil {
		fmt.Println("Failed to start server")
	}
}

func BeginRegistration(c *gin.Context) {

	// get username/friendly Name
	username := c.Param("email")

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// store session data
	session := sessions.Default(c)
	session.Set("sessionData", sessionData)
	err = session.Save()
	if err != nil {
		log.Println("Store sessionData:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, options.Response)
}

func FinishRegistration(c *gin.Context) {

	// get username
	username := c.Param("email")

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// load the session data
	session := sessions.Default(c)
	sessionData := session.Get("sessionData").(webauthn.SessionData)

	credential, err := webAuthn.FinishRegistration(user, sessionData, c.Request)
	if err != nil {
		log.Println("Error in FinishRegistration:", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	user.AddCredential(*credential)

	c.JSON(http.StatusOK, gin.H{"status": "registration successful"})
}

func BeginLogin(c *gin.Context) {

	// get username
	username := c.Param("email")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// store session data
	session := sessions.Default(c)
	session.Set("sessionData", sessionData)
	err = session.Save()
	if err != nil {
		log.Println("Store sessionData:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, options.Response)
}

func FinishLogin(c *gin.Context) {

	// get username
	username := c.Param("email")

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// load the session data
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

	// successful login
	c.JSON(http.StatusOK, gin.H{"status": "login successful"})
}

func Wrap(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
