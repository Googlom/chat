// Package REST provides authentication by calling a separate process over REST API.
package phone

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/store"
	"github.com/tinode/chat/server/store/types"
)

// authenticator is the type to map authentication methods to.
type authenticator struct {
	// Logical name of this authenticator
	name      string
	addToTags bool
}

const (
	// codeLength = log10(maxCodeValue)
	codeLength   = 6
	maxCodeValue = 999999
)

type configType struct {
	// AddToTags indicates that the user name should be used as a searchable tag.
	AddToTags bool `json:"add_to_tags"`
}

// Init initializes the handler.
func (a *authenticator) Init(jsonconf json.RawMessage, name string) error {
	if a.name != "" {
		return errors.New("auth_phone: already initialized as " + a.name + "; " + name)
	}

	var config configType
	if err := json.Unmarshal(jsonconf, &config); err != nil {
		return errors.New("auth_phone: failed to parse config: " + err.Error() + "(" + string(jsonconf) + ")")
	}

	a.addToTags = config.AddToTags
	a.name = name

	return nil
}

func parseSecret(bsecret []byte) (string, string, error) {
	secret := string(bsecret)
	var phoneNumber, response string

	splitAt := strings.Index(secret, ":")
	if splitAt < 0 {
		phoneNumber = secret
	} else {
		phoneNumber = strings.ToLower(secret[:splitAt])
		response = secret[splitAt+1:]
	}

	// E.164 international phone number formatting regex
	if match, _ := regexp.MatchString(`^\+?[1-9]\d{1,14}$`, phoneNumber); !match {
		return "", "", types.ErrMalformed
	}

	return phoneNumber, response, nil
}

func genResponse() string {
	// Generate expected response as a random numeric string between 0 and 999999
	r, _ := rand.Int(rand.Reader, big.NewInt(int64(maxCodeValue)))
	randString := r.String()
	return strings.Repeat("0", codeLength-len(randString)) + randString
}

func sendSMS(to, code string) error {
	log.Printf("<<<SMS>>> Sent to %s with code '%s' ", to, code)
	return nil
}

func (a *authenticator) addRecord(rec *auth.Rec, phoneNumber string) (*auth.Rec, error) {
	response := genResponse()

	rec.Features = auth.FeatureNoLogin
	rec.AuthLevel = auth.LevelAnon
	// TODO: make lifetime period configurable
	rec.Lifetime = 60 * time.Second

	if err := store.Users.AddAuthRecord(rec.Uid,
		auth.LevelAnon,
		a.name,
		phoneNumber+":temp",
		[]byte(response),
		types.TimeNow().Add(rec.Lifetime),
	); err != nil {
		return nil, err
	}

	_ = sendSMS(phoneNumber, response)
	return rec, nil
}

// AddRecord adds persistent authentication record to the database.
// Returns: updated auth record, error
func (a *authenticator) AddRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	phoneNumber, _, err := parseSecret(secret)
	if err != nil {
		return nil, err
	}

	return a.addRecord(rec, phoneNumber)
}

// UpdateRecord updates existing record with new credentials.
func (a *authenticator) UpdateRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	return rec, nil
}

func (a *authenticator) getAuthDetails(phoneNumber string, tempOnly bool) (types.Uid, string, time.Time, error) {
	if tempOnly {
		// get temporary (unconfirmed) record
		uid, _, needResp, expires, err := store.Users.GetAuthUniqueRecord(a.name, phoneNumber+":temp")
		return uid, string(needResp), expires, err
	} else {
		// get persistent or temp record
		uid, _, needResp, _, err := store.Users.GetAuthUniqueRecord(a.name, phoneNumber)
		return uid, string(needResp), time.Time{}, err
	}
}

// Authenticate: get user record by provided secret
func (a *authenticator) Authenticate(secret []byte) (*auth.Rec, []byte, error) {
	phoneNumber, response, err := parseSecret(secret)
	if err != nil {
		return nil, nil, err
	}

	if response == "" {
		uid, _, _, err := a.getAuthDetails(phoneNumber, false)
		if err != nil {
			return nil, nil, err
		}

		if uid.IsZero() {
			return nil, nil, types.ErrFailed
		}

		// start by creating temporary auth record in db which will be deleted after successfull confirmation or expiry
		rec := new(auth.Rec)
		rec.Uid = uid

		// SMS request
		rec, err = a.addRecord(rec, phoneNumber)
		return rec, []byte("validate credentials"), err
	} else {
		// confirmation request

		uid, needResp, expires, err := a.getAuthDetails(phoneNumber, true)
		if err != nil {
			return nil, nil, err
		}

		if uid.IsZero() {
			// There is no temporary record in db
			return nil, nil, types.ErrFailed
		}

		if !expires.IsZero() && expires.Before(time.Now()) {
			// The record has expired
			// TODO: Delete expired record here too
			return nil, nil, types.ErrExpired
		}

		if response != needResp {
			return nil, nil, types.ErrInvalidResponse
		}

		// Confirmation successfull
		rec := new(auth.Rec)
		rec.Uid = uid
		rec.AuthLevel = auth.LevelAuth
		rec.Features = auth.FeatureValidated

		err = store.Users.UpdateAuthRecord(rec.Uid, rec.AuthLevel, a.name, phoneNumber, nil, time.Time{})
		//TODO: delete temp auth and make current persistent (expire = Zero, secret = nil)
		return rec, nil, err
	}
}

// IsUnique verifies if the provided secret can be considered unique by the auth scheme
// E.g. if login is unique.
func (a *authenticator) IsUnique(secret []byte) (bool, error) {
	phoneNumber, _, err := parseSecret(secret)
	if err != nil {
		return false, err
	}

	uid, _, _, _, err := store.Users.GetAuthUniqueRecord(a.name, phoneNumber)
	if err != nil {
		return false, err
	}

	if !uid.IsZero() {
		return false, types.ErrDuplicate
	}

	return true, nil
}

// GenSecret generates a new secret, if appropriate.
func (a *authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
	return nil, time.Time{}, types.ErrUnsupported
}

// DelRecords deletes all authentication records for the given user.
func (a *authenticator) DelRecords(uid types.Uid) error {
	//return store.Users.DelAuthRecords(uid, a.name)
	return nil
}

// RestrictedTags returns tag namespaces restricted by the server.
func (a *authenticator) RestrictedTags() ([]string, error) {
	var tags []string
	if a.addToTags {
		tags = []string{a.name}
	}
	return tags, nil
}

// GetResetParams returns authenticator parameters passed to password reset handler
// (none for rest).
func (authenticator) GetResetParams(uid types.Uid) (map[string]interface{}, error) {
	// TODO: route request to the server.
	return nil, nil
}

func init() {
	store.RegisterAuthScheme("phone", &authenticator{})
}
