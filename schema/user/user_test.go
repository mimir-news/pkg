package user_test

import (
	"testing"

	"github.com/mimir-news/pkg/id"
	"github.com/mimir-news/pkg/schema/user"
)

func TestUserValid(t *testing.T) {
	validUser := user.User{
		ID:    id.New(),
		Email: "some-mail",
	}
	isValid := validUser.Valid()
	if !isValid {
		t.Error("User was invalid but should be ok.", validUser)
	}

	invalidUser := user.User{}
	isValid = invalidUser.Valid()
	if isValid {
		t.Error("User was valid but should not be.", invalidUser)
	}
}

func TestCredentialsValid(t *testing.T) {
	validCreds := user.Credentials{
		Email:    "some@mail.com",
		Password: "super-secret-password",
	}
	isValid := validCreds.Valid()
	if !isValid {
		t.Error("Credendtials were invalid but should be ok.", validCreds)
	}

	invalidCreds := user.Credentials{}
	isValid = invalidCreds.Valid()
	if isValid {
		t.Error("Credendtials were valid but should not be.", invalidCreds)
	}

	invalidCreds = user.Credentials{Email: "email"}
	isValid = invalidCreds.Valid()
	if isValid {
		t.Error("Credendtials were valid but should not be.", invalidCreds)
	}

	invalidCreds = user.Credentials{Password: "ok-password"}
	isValid = invalidCreds.Valid()
	if isValid {
		t.Error("Credendtials were valid but should not be.", invalidCreds)
	}

	toShortCreds := user.Credentials{
		Email:    "some@mail.com",
		Password: "short",
	}
	isValid = toShortCreds.Valid()
	if isValid {
		t.Error("Credendtials were invalid but should be ok.", toShortCreds)
	}
}

func TestPasswordChangeValid(t *testing.T) {
	validChange := user.PasswordChange{
		New:      "some long pwd",
		Repeated: "some long pwd",
		Old: user.Credentials{
			Email:    "some@mail.com",
			Password: "super-secret-password",
		},
	}
	isValid := validChange.Valid()
	if !isValid {
		t.Error("PasswordChange were invalid but should be ok.", validChange)
	}

	validChange = user.PasswordChange{
		New:      "some long pwd",
		Repeated: "some other long pwd",
		Old: user.Credentials{
			Email:    "some@mail.com",
			Password: "super-secret-password",
		},
	}
	isValid = validChange.Valid()
	if !isValid {
		t.Error("PasswordChange were invalid but should be ok.", validChange)
	}

	invalidChange := user.PasswordChange{
		New:      "short",
		Repeated: "some other long pwd",
		Old: user.Credentials{
			Email:    "some@mail.com",
			Password: "super-secret-password",
		},
	}
	isValid = invalidChange.Valid()
	if isValid {
		t.Error("PasswordChange were valid but should not be.", invalidChange)
	}

	invalidChange = user.PasswordChange{}
	isValid = invalidChange.Valid()
	if isValid {
		t.Error("PasswordChange were valid but should not be.", invalidChange)
	}

}
