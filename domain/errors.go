package domain

import (
	"net/http"

	kiterrors "github.com/quocdaitrn/golang-kit/errors"
	httperrors "github.com/quocdaitrn/golang-kit/http/errors"
)

// List of error code used in authentication service.
const (
	ErrCodeIncorrectPassword = iota + 10200
	ErrCodeRegisterEmailAlreadyExist
)

var (
	//ErrIncorrectPassword is an error occurs when user logins with an incorrect password.
	ErrIncorrectPassword = kiterrors.NewErrorWithUserMessage(ErrCodeIncorrectPassword, "incorrect password", "Auth_User_Login_incorrect_password")

	//ErrRegisterEmailAlreadyExist is an error occurs when user register a new account with an email already exist.
	ErrRegisterEmailAlreadyExist = kiterrors.NewErrorWithUserMessage(ErrCodeRegisterEmailAlreadyExist, "email has already registered", "Auth_User_Register_email_exist")
)

// List of HTTP errors used in authentication service.
//
// HTTP details error code [4xx200, 4xx300) is reserved code for authentication
// service.
var (
	HTTPErrIncorrectPassword         = httperrors.NewHTTPError(http.StatusBadRequest, 400200, "Incorrect password")
	HTTPErrRegisterEmailAlreadyExist = httperrors.NewHTTPError(http.StatusBadRequest, 400201, "Email has already registered")
)

// init setups and mappings auth error's to error handling transports (http).
func init() {
	kiterrors.AddBusinessError(ErrCodeIncorrectPassword)
	kiterrors.AddBusinessError(ErrCodeRegisterEmailAlreadyExist)

	httperrors.AddErrorHTTPErrorMapping(ErrIncorrectPassword, HTTPErrIncorrectPassword)
	httperrors.AddErrorHTTPErrorMapping(ErrRegisterEmailAlreadyExist, HTTPErrRegisterEmailAlreadyExist)
}
