package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

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
	var finishRegistrationRequest *FinishRegistrationRequest
	if err := c.BindJSON(&finishRegistrationRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := finishRegistrationRequest.Name

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

	response, err := reqToWebAuthn(c.Request, finishRegistrationRequest.Response)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, response)
	if err != nil {
		log.Println("Error in FinishRegistration:", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	user.AddCredential(*credential)

	c.JSON(http.StatusOK, gin.H{"verified": true})
}

func BeginLogin(c *gin.Context) {

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

	var finishAuthenticationRequest *FinishAuthenticationRequest

	if err := c.BindJSON(&finishAuthenticationRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	username := finishAuthenticationRequest.Name

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := reqToWebAuthn(c.Request, finishAuthenticationRequest.Response)
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
	_, err = webAuthn.FinishLogin(user, sessionData, response)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// handle successful login
	c.JSON(http.StatusOK, gin.H{"verified": true})

}

func Wrap(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func reqToWebAuthn(r *http.Request, response interface{}) (req *http.Request, err error) {
	var (
		body []byte
	)
	if body, err = json.Marshal(response); err == nil {

		req = &http.Request{
			Method:        r.Method,
			URL:           r.URL,
			Proto:         r.Proto,
			ProtoMajor:    r.ProtoMajor,
			ProtoMinor:    r.ProtoMinor,
			Header:        r.Header,
			Body:          io.NopCloser(bytes.NewBuffer(body)),
			ContentLength: int64(len(body)),
		}
	}
	return
}
