package eskiz_uz

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/tinode/chat/server/store"
)

type SmsAdp struct {
	username string
	password string
	accToken string
}

// Init runs on goroutine because initialization performs external calls. All errors are logged
func (a *SmsAdp) Init(username, password string) {
	a.username, a.password = username, password

	if err := a.initToken(); err != nil {
		log.Println("SmsAdp init error: ", err)
	}
}

func (a *SmsAdp) initToken() error {
	token := store.SmsGetAdpToken()
	if token == "" {
		return a.loginRequest()
	}

	if err := a.checkToken(token); err != nil {
		return err
	}

	a.accToken = token
	return nil
}

func (a *SmsAdp) writeToken(token string) error {
	a.pruneTokens()
	if err := store.SmsWriteAdpToken(token); err != nil {
		return err
	}

	a.accToken = token
	return nil
}

func (a *SmsAdp) pruneTokens() {
	client := http.Client{}
	tokens := store.SmsGetPruneTokens()
	for _, token := range tokens {
		req, _ := http.NewRequest("DELETE", "https://notify.eskiz.uz/api/auth/invalidate", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, _ = client.Do(req)
	}
}

func (a *SmsAdp) SendSMS(to, code string) {
	msg := "# " + code + " - Vash kod podtverjdeniya. Nikomu ne soobshayte kod."
	if err := a.send(to, msg, false); err != nil {
		log.Println("SMS adp error:", err)
	}
}

func (a *SmsAdp) send(phone, message string, noLogin bool) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("mobile_phone", phone)
	_ = writer.WriteField("message", message)
	req, err := http.NewRequest("POST", "https://notify.eskiz.uz/api/message/sms/send", body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+a.accToken)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		if noLogin {
			return errors.New("not sent: " + resp.Status)
		}

		if err = a.loginRequest(); err != nil {
			return err
		}

		return a.send(phone, message, true)
	}

	return nil
}

func (a *SmsAdp) checkToken(token string) error {
	req, err := http.NewRequest("GET", "https://notify.eskiz.uz/api/auth/user", nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return a.loginRequest()
	}

	return nil
}

func (a *SmsAdp) loginRequest() error {
	resp, err := http.PostForm("https://notify.eskiz.uz/api/auth/login", url.Values{
		"email":    {a.username},
		"password": {a.password},
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("Error response: " + resp.Status)
	}

	var result struct {
		Message string
		Data    map[string]string
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return err
	}

	if result.Message != "token_generated" {
		return errors.New("something wrong: message = '" + result.Message + "'")
	}

	return a.writeToken(result.Data["token"])
}
