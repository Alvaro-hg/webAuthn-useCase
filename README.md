# WebAuthn basic Login and Register example

This is a modification of the [WebAuthn Basic Client/Server Example (go)](https://github.com/hbolimovsky/webauthn-example) proyect. This version makes use of the Gin Web Framwork.

## Set-up

### Download

Download the project (i.e. via `git clone` or `go get`) and navigate to the project's root directory. 

### Start

Start the server by compiling and running the code:

```bash
$ go run .
2019/04/01 11:45:09 starting server at :8080
```

### Test

#### Spin Up

Go to [localhost:8080](http://localhost:8080).

If the web browser you are using doesn't support WebAuthn switch to another one like Chrome or Safari.

#### Register

To test that the demo is working properly, enter an email like `foo@bar.com` and press the `Register` button. You should be prompted to use some authenticator like fingerprint, pin...

Upon successful registration, you'll see an alert saying you successfully registered.

#### Login

Press the login button and follow the instructions. The login process is identical (user side) to the registration process.
