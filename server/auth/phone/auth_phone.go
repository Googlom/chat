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

	// key is phone number
	smsTimers map[string]*time.Timer
}

const (
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

// Parse incoming secret to phone number and response code. Example: +999887766554:123456
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

// genResponse generates expected response as a random numeric string between 0 and 999999
func genResponse() string {
	r, _ := rand.Int(rand.Reader, big.NewInt(int64(maxCodeValue)))
	randString := r.String()
	return strings.Repeat("0", codeLength-len(randString)) + randString
}

// TODO: implement
// Actually send SMS with response code
func sendSMS(to, code string) error {
	log.Printf("<<<SMS>>> Sent to %s with code '%s' ", to, code)
	return nil
}

func (a *authenticator) startTimerForPhone(phoneNumber string, dur time.Duration) {
}

func (a *authenticator) getAuthDetails(phoneNumber string, tempOnly bool) (types.Uid, string, time.Time, error) {
	if tempOnly {
		// get temporary (unconfirmed) record
		uid, _, needResp, expires, err := store.Users.GetAuthUniqueRecord(a.name+"_temp", phoneNumber)
		return uid, string(needResp), expires, err
	} else {
		// get persistent or temp record
		uid, _, needResp, _, err := store.Users.GetAuthUniqueRecord(a.name+"_any", phoneNumber)
		return uid, string(needResp), time.Time{}, err
	}
}

func (a *authenticator) addRecord(rec *auth.Rec, phoneNumber string) (*auth.Rec, error) {
	// Now we are creating temp record that will be deleted after successfull confirmation or timer expiry
	rec.Features = auth.FeatureNoLogin
	rec.AuthLevel = auth.LevelAnon
	// TODO: make lifetime period configurable
	rec.Lifetime = 60 * time.Second

	response := genResponse()
	if err := store.Users.AddAuthRecord(rec.Uid,
		auth.LevelAnon,
		a.name+"_temp",
		phoneNumber,
		[]byte(response),
		types.TimeNow().Add(rec.Lifetime),
	); err != nil {
		return nil, err
	}

	// Start timer which will delete unconfirmed record after it expires.
	a.smsTimers[phoneNumber] = time.AfterFunc(rec.Lifetime, func() {
		store.Users.AuthDelPhoneTemp(phoneNumber)

		// reset the timer for this phone number
		delete(a.smsTimers, phoneNumber)
	})
	// TODO: Send sms in goroutine with error responding
	_ = sendSMS(phoneNumber, response)

	return rec, nil
}

// updateRecord makes temporary record persistent
func (a *authenticator) updateRecord(rec *auth.Rec, phoneNumber string) error {
	err := store.Users.AddAuthRecord(rec.Uid, rec.AuthLevel, a.name, phoneNumber, nil, time.Time{})
	if err != nil && err == types.ErrDuplicate {
		// Do nothing if record exists - no values should change during 'update'
		return nil
	}

	return err
}

// AddRecord used only when creating new user
func (a *authenticator) AddRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	phoneNumber, _, err := parseSecret(secret)
	if err != nil {
		return nil, err
	}

	// Prevent creating another record before first expires
	if _, ok := a.smsTimers[phoneNumber]; ok {
		return rec, types.ErrTimerNotExpired
	}

	if a.addToTags {
		rec.Tags = append(rec.Tags, a.name+":"+phoneNumber)
	}

	return a.addRecord(rec, phoneNumber)
}

// Authenticate used in two ways:
// 1) Requesting sms code to log in from new device. In this case secret should contain only phone number
// 2) Confirming phone number. In this case secret should be in format "phoneNumber:responseCode"
func (a *authenticator) Authenticate(secret []byte) (*auth.Rec, []byte, error) {
	phoneNumber, response, err := parseSecret(secret)
	if err != nil {
		return nil, nil, err
	}

	if response == "" {
		// 1) Requesting sms code

		if _, ok := a.smsTimers[phoneNumber]; ok {
			return nil, nil, types.ErrTimerNotExpired
		}

		uid, _, _, err := a.getAuthDetails(phoneNumber, false)
		if err != nil {
			return nil, nil, err
		}

		if uid.IsZero() {
			// No auth record in DB
			return nil, nil, types.ErrFailed
		}

		// start by creating temporary auth record in db which will be deleted after successfull confirmation or expiry
		rec := new(auth.Rec)
		rec.Uid = uid
		rec, err = a.addRecord(rec, phoneNumber)

		return rec, []byte("validate credentials"), err
	} else {
		//2) Confirming phone number.

		uid, expected, expires, err := a.getAuthDetails(phoneNumber, true)
		if err != nil {
			return nil, nil, err
		}

		if uid.IsZero() {
			// There is no temporary record in db
			return nil, nil, types.ErrFailed
		}

		if !expires.IsZero() && expires.Before(time.Now()) {
			// The record has expired
			store.Users.AuthDelPhoneTemp(phoneNumber)
			return nil, nil, types.ErrExpired
		}

		if response != expected {
			return nil, nil, types.ErrInvalidResponse
		}

		// Confirmation successfull
		rec := new(auth.Rec)
		rec.Uid = uid
		rec.AuthLevel = auth.LevelAuth
		rec.Features = auth.FeatureValidated

		err = a.updateRecord(rec, phoneNumber)
		store.Users.AuthDelPhoneTemp(phoneNumber)

		// Stop the timer to prevent calling store.Users.AuthDelPhoneTemp() again.
		a.smsTimers[phoneNumber].Stop()
		delete(a.smsTimers, phoneNumber)

		return rec, nil, err
	}
}

// IsUnique verifies if the provided phone number considered unique
func (a *authenticator) IsUnique(secret []byte) (bool, error) {
	phoneNumber, _, err := parseSecret(secret)
	if err != nil {
		return false, err
	}

	uid, _, _, err := a.getAuthDetails(phoneNumber, false)
	if err != nil {
		return false, err
	}

	if !uid.IsZero() {
		return false, types.ErrDuplicate
	}

	return true, nil
}

// RestrictedTags returns tag namespaces restricted by the server.
func (a *authenticator) RestrictedTags() ([]string, error) {
	var tags []string
	if a.addToTags {
		tags = []string{a.name}
	}
	return tags, nil
}

func init() {
	store.RegisterAuthScheme("phone", &authenticator{})
}

// Below methods are unused by this authenticator
func (a *authenticator) UpdateRecord(rec *auth.Rec, secret []byte) (*auth.Rec, error) {
	return rec, nil
}

func (a *authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
	return nil, time.Time{}, types.ErrUnsupported
}

func (a *authenticator) DelRecords(uid types.Uid) error {
	return nil
}

func (authenticator) GetResetParams(uid types.Uid) (map[string]interface{}, error) {
	return nil, nil
}
