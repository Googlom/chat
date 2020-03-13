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

	// key = phoneNumber
	smsTimers map[string]*time.Timer
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
	a.smsTimers = map[string]*time.Timer{}

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

// TODO: Move this functionality to db adapter
func (a *authenticator) deleteTempRecord(phoneNumber string) {
	uid, _, _, _, _ := store.Users.GetAuthUniqueRecord("phone", phoneNumber)
	if uid.IsZero() {
		// There is no persistent auth record (user incomplete).
		// Get Uid from temporary record and delete previously created user and auth record.
		uid, _, _, _, _ = store.Users.GetAuthUniqueRecord("phone_temp", phoneNumber)
		_ = store.Users.Delete(uid, true)
	}

	// There is a persistent auth record (user complete).
	// Just delete temporary record
	_ = store.Users.DelAuthRecords(uid, "phone_temp")
}

func (a *authenticator) startTimerForPhone(phoneNumber string, dur time.Duration) {
	a.smsTimers[phoneNumber] = time.AfterFunc(dur, func() {
		a.deleteTempRecord(phoneNumber)

		// reset the timer for this phone number
		delete(a.smsTimers, phoneNumber)
	})
}

func (a *authenticator) addRecord(rec *auth.Rec, phoneNumber string) (*auth.Rec, error) {
	response := genResponse()

	rec.Features = auth.FeatureNoLogin
	rec.AuthLevel = auth.LevelAnon
	// TODO: make lifetime period configurable
	rec.Lifetime = 60 * time.Second

	if err := store.Users.AddAuthRecord(rec.Uid,
		auth.LevelAnon,
		a.name+"_temp",
		phoneNumber,
		[]byte(response),
		types.TimeNow().Add(rec.Lifetime),
	); err != nil {
		return nil, err
	}

	a.startTimerForPhone(phoneNumber, rec.Lifetime)
	_ = sendSMS(phoneNumber, response)

	return rec, nil
}

func (a *authenticator) AddRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	phoneNumber, _, err := parseSecret(secret)
	if err != nil {
		return nil, err
	}

	if _, ok := a.smsTimers[phoneNumber]; ok {
		return rec, types.ErrTimerNotExpired
	}

	return a.addRecord(rec, phoneNumber)
}

// UpdateRecord updates existing record with new credentials.
func (a *authenticator) UpdateRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	return rec, nil
}

func (a *authenticator) updateRecord(rec *auth.Rec, phoneNumber string) error {
	err := store.Users.AddAuthRecord(rec.Uid, rec.AuthLevel, a.name, phoneNumber, nil, time.Time{})
	if err != nil && err == types.ErrDuplicate {
		// Do nothing if record exists - no values should change during 'update'
		return nil
	}

	return err
}

func (a *authenticator) getAuthDetails(phoneNumber string, tempOnly bool) (types.Uid, string, time.Time, error) {
	if tempOnly {
		// get temporary (unconfirmed) record
		uid, _, needResp, expires, err := store.Users.GetAuthUniqueRecord(a.name+"_temp", phoneNumber)
		return uid, string(needResp), expires, err
	} else {
		// get persistent or temp record
		uid, _, needResp, _, err := store.Users.GetAuthUniqueRecord(a.name, phoneNumber)
		return uid, string(needResp), time.Time{}, err
	}
}

func (a *authenticator) Authenticate(secret []byte) (*auth.Rec, []byte, error) {
	phoneNumber, response, err := parseSecret(secret)
	if err != nil {
		return nil, nil, err
	}

	if response == "" {
		if _, ok := a.smsTimers[phoneNumber]; ok {
			return nil, nil, types.ErrTimerNotExpired
		}

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
			a.deleteTempRecord(phoneNumber)
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

		err = a.updateRecord(rec, phoneNumber)
		//a.deleteTempRecord(phoneNumber)
		return rec, nil, err
	}
}

// IsUnique verifies if the provided secret can be considered unique by the auth scheme
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
