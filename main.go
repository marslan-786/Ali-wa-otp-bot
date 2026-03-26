package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

var client *whatsmeow.Client
var container *sqlstore.Container
var otpDB *sql.DB 

// ================= پینل 1 کے ویری ایبلز =================
var isFirstRunPanel1 = true
var directAPIClient *http.Client
var currentSessKeyPanel1 string 

// ================= پینل 2 (Number Panel) کے ویری ایبلز =================
var isFirstRunPanel2 = true
var npAPIClient *http.Client
var currentSessKeyPanel2 string
const NPBaseURL = "http://51.89.99.105/NumberPanel"

// ================= HTTP کلائنٹس Setup =================

func initClients() {
	jar1, _ := cookiejar.New(nil)
	directAPIClient = &http.Client{
		Jar:     jar1,
		Timeout: 15 * time.Second,
	}

	jar2, _ := cookiejar.New(nil)
	npAPIClient = &http.Client{
		Jar:     jar2,
		Timeout: 15 * time.Second,
	}
}

// ================= پینل 1 (SMS Hadi) کی لاجک =================

func loginToPanel1() bool {
	fmt.Println("🔄 [Auth-P1] Attempting to login to Panel 1 (SMS Hadi)...")
	loginURL := "http://185.2.83.39/ints/login"
	signinURL := "http://185.2.83.39/ints/signin"
	reportsURL := "http://185.2.83.39/ints/agent/SMSCDRReports"

	resp, err := directAPIClient.Get(loginURL)
	if err != nil {
		fmt.Println("❌ [Auth-P1] Login Page Fetch Error:", err)
		return false
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	re := regexp.MustCompile(`What is (\d+)\s*\+\s*(\d+)\s*=\s*\?`)
	matches := re.FindStringSubmatch(string(bodyBytes))
	
	captchaAnswer := "11"
	if len(matches) == 3 {
		num1, _ := strconv.Atoi(matches[1])
		num2, _ := strconv.Atoi(matches[2])
		captchaAnswer = strconv.Itoa(num1 + num2)
		fmt.Printf("🧠 [Auth-P1] Captcha Solved: %s + %s = %s\n", matches[1], matches[2], captchaAnswer)
	}

	formData := url.Values{}
	formData.Set("username", "opxali")
	formData.Set("password", "opxali00")
	formData.Set("capt", captchaAnswer)

	req, _ := http.NewRequest("POST", signinURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	req.Header.Set("Referer", loginURL)

	resp2, err := directAPIClient.Do(req)
	if err != nil {
		fmt.Println("❌ [Auth-P1] Signin Error:", err)
		return false
	}
	resp2.Body.Close()

	reqReports, _ := http.NewRequest("GET", reportsURL, nil)
	reqReports.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	
	respReports, err := directAPIClient.Do(reqReports)
	if err == nil {
		reportsBody, _ := io.ReadAll(respReports.Body)
		respReports.Body.Close()
		keyRegex := regexp.MustCompile(`sesskey=([a-zA-Z0-9=]+)`)
		keyMatches := keyRegex.FindStringSubmatch(string(reportsBody))
		if len(keyMatches) >= 2 {
			currentSessKeyPanel1 = keyMatches[1]
			fmt.Println("✅ [Auth-P1] Successfully Logged in & Session Saved!")
			return true
		}
	}
	return false
}

func fetchPanel1Data() ([]interface{}, bool) {
	if currentSessKeyPanel1 == "" {
		return nil, false
	}
	now := time.Now()
	dateStr := now.Format("2006-01-02")
	fetchURL := fmt.Sprintf("http://185.2.83.39/ints/agent/res/data_smscdr.php?fdate1=%s%%2000:00:00&fdate2=%s%%2023:59:59&sEcho=1&iColumns=9&iDisplayStart=0&iDisplayLength=25&sesskey=%s", dateStr, dateStr, currentSessKeyPanel1)

	req, _ := http.NewRequest("GET", fetchURL, nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")

	resp, err := directAPIClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.Request.URL.Path == "/ints/login" || resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false
	}
	if data != nil && data["aaData"] != nil {
		return data["aaData"].([]interface{}), true
	}
	return nil, true
}

// ================= پینل 2 (Number Panel) کی لاجک =================

func loginToPanel2() bool {
	fmt.Println("🔄 [Auth-P2] Attempting to login to Panel 2 (Number Panel)...")
	loginURL := NPBaseURL + "/login"
	signinURL := NPBaseURL + "/signin"
	reportsURL := NPBaseURL + "/client/SMSCDRStats"

	resp, err := npAPIClient.Get(loginURL)
	if err != nil {
		fmt.Println("❌ [Auth-P2] Login Page Fetch Error:", err)
		return false
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	re := regexp.MustCompile(`What is (\d+)\s*\+\s*(\d+)\s*=\s*\?`)
	matches := re.FindStringSubmatch(string(bodyBytes))
	
	captchaAnswer := "11"
	if len(matches) == 3 {
		num1, _ := strconv.Atoi(matches[1])
		num2, _ := strconv.Atoi(matches[2])
		captchaAnswer = strconv.Itoa(num1 + num2)
		fmt.Printf("🧠 [Auth-P2] Captcha Solved: %s + %s = %s\n", matches[1], matches[2], captchaAnswer)
	}

	formData := url.Values{}
	formData.Set("username", "Kami522")
	formData.Set("password", "Kami526")
	formData.Set("capt", captchaAnswer)

	req, _ := http.NewRequest("POST", signinURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	req.Header.Set("Referer", loginURL)

	resp2, err := npAPIClient.Do(req)
	if err != nil {
		fmt.Println("❌ [Auth-P2] Signin Error:", err)
		return false
	}
	resp2.Body.Close()

	reqReports, _ := http.NewRequest("GET", reportsURL, nil)
	reqReports.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	reqReports.Header.Set("Referer", NPBaseURL+"/client/SMSDashboard")
	
	respReports, err := npAPIClient.Do(reqReports)
	if err == nil {
		reportsBody, _ := io.ReadAll(respReports.Body)
		respReports.Body.Close()
		keyRegex := regexp.MustCompile(`sesskey=([a-zA-Z0-9%=]+)`)
		keyMatches := keyRegex.FindStringSubmatch(string(reportsBody))
		if len(keyMatches) >= 2 {
			currentSessKeyPanel2 = keyMatches[1]
			fmt.Println("✅ [Auth-P2] Successfully Logged in & Session Saved!")
			return true
		}
	}
	return false
}

func fetchPanel2Data() ([]interface{}, bool) {
	if currentSessKeyPanel2 == "" {
		return nil, false 
	}
	
	now := time.Now()
	dateStr := now.Format("2006-01-02")
	
	params := url.Values{}
	params.Set("fdate1", dateStr+" 00:00:00")
	params.Set("fdate2", dateStr+" 23:59:59")
	params.Set("sesskey", currentSessKeyPanel2)
	params.Set("sEcho", "2")
	params.Set("iColumns", "7")
	params.Set("iDisplayStart", "0")
	params.Set("iDisplayLength", "-1")

	finalURL := NPBaseURL + "/client/res/data_smscdr.php?" + params.Encode()

	req, _ := http.NewRequest("GET", finalURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := npAPIClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("<!DOCTYPE HTML>")) || bytes.Contains(body, []byte("<html")) {
		return nil, false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, false
	}
	if data != nil && data["aaData"] != nil {
		return data["aaData"].([]interface{}), true
	}
	return nil, true
}

// ================= SQLite ڈیٹا بیس Setup =================

func initSQLiteDB() {
	var err error
	otpDB, err = sql.Open("sqlite3", "file:/app/data/kami_session.db?_foreign_keys=on")
	if err != nil {
		panic(fmt.Sprintf("❌ Failed to open SQLite DB: %v", err))
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS sent_otps (
		msg_id TEXT PRIMARY KEY,
		sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	
	_, err = otpDB.Exec(createTableQuery)
	if err != nil {
		panic(fmt.Sprintf("❌ Failed to create table: %v", err))
	}
	fmt.Println("🗄️ [DB] Local SQLite Database Initialized for Sent OTPs!")
}

func isAlreadySent(id string) bool {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sent_otps WHERE msg_id = ?)`
	err := otpDB.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func markAsSent(id string) {
	query := `INSERT OR IGNORE INTO sent_otps (msg_id) VALUES (?)`
	otpDB.Exec(query, id)
}

// ================= Helper Functions =================

func extractOTP(msg string) string {
	re := regexp.MustCompile(`\b\d{3,4}[-\s]?\d{3,4}\b|\b\d{4,8}\b`)
	return re.FindString(msg)
}

func maskPhoneNumber(phone string) string {
	if len(phone) < 6 {
		return phone
	}
	return fmt.Sprintf("%s•••%s", phone[:3], phone[len(phone)-4:])
}

func cleanCountryName(name string) string {
	if name == "" {
		return "Unknown"
	}
	parts := strings.Fields(strings.Split(name, "-")[0])
	if len(parts) > 0 {
		return parts[0]
	}
	return "Unknown"
}

// ================= Monitoring Loop (Panel 1) =================

func checkPanel1OTPs(cli *whatsmeow.Client) {
	fmt.Println("📡 [P1] Calling SMS API...")
	aaData, success := fetchPanel1Data()
	
	if !success {
		fmt.Println("⚠️ [P1] Session Expired. Triggering Re-login...")
		loginToPanel1()
		return
	}

	if len(aaData) == 0 {
		fmt.Println("ℹ️ [P1] No data array found.")
		return
	}

	if isFirstRunPanel1 {
		fmt.Println("🚀 [P1-Boot] Caching old messages...")
		for i, row := range aaData {
			r, ok := row.([]interface{})
			if !ok || len(r) < 6 { continue }

			rawTime := fmt.Sprintf("%v", r[0])
			phone := fmt.Sprintf("%v", r[2])
			msgID := fmt.Sprintf("%v_%v", phone, rawTime)

			if i == 0 { // Send the very first active check message
				sendWhatsAppMessage(cli, r, msgID, true, 5) // index 5 for full message
			}
			markAsSent(msgID)
		}
		isFirstRunPanel1 = false
		fmt.Printf("✅ [P1-Boot] %d old messages cached.\n", len(aaData))
		return
	}

	newMsgsCount := 0
	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 6 { continue }

		rawTime := fmt.Sprintf("%v", r[0])
		phone := fmt.Sprintf("%v", r[2])
		msgID := fmt.Sprintf("%v_%v", phone, rawTime)

		if isAlreadySent(msgID) { continue }

		newMsgsCount++
		sendWhatsAppMessage(cli, r, msgID, false, 5) // index 5 for msg
	}

	if newMsgsCount == 0 {
		fmt.Println("ℹ️ [P1] No NEW messages found.")
	} else {
		fmt.Printf("🎉 [P1] Processed %d NEW messages!\n", newMsgsCount)
	}
}

// ================= Monitoring Loop (Panel 2) =================

func checkPanel2OTPs(cli *whatsmeow.Client) {
	fmt.Println("📡 [P2] Calling Number Panel API...")
	aaData, success := fetchPanel2Data()
	
	if !success {
		fmt.Println("⚠️ [P2] Session Expired. Triggering Re-login...")
		loginToPanel2()
		return
	}

	if len(aaData) == 0 {
		fmt.Println("ℹ️ [P2] No data array found.")
		return
	}

	if isFirstRunPanel2 {
		fmt.Println("🚀 [P2-Boot] Caching old messages...")
		for i, row := range aaData {
			r, ok := row.([]interface{})
			if !ok || len(r) < 5 { continue }

			rawTime := fmt.Sprintf("%v", r[0])
			phone := fmt.Sprintf("%v", r[2])
			msgID := fmt.Sprintf("P2_%v_%v", phone, rawTime) // prefix P2 to avoid overlap

			if i == 0 { 
				sendWhatsAppMessage(cli, r, msgID, true, 4) // index 4 for msg in panel 2
			}
			markAsSent(msgID)
		}
		isFirstRunPanel2 = false
		fmt.Printf("✅ [P2-Boot] %d old messages cached.\n", len(aaData))
		return
	}

	newMsgsCount := 0
	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 5 { continue }

		rawTime := fmt.Sprintf("%v", r[0])
		phone := fmt.Sprintf("%v", r[2])
		msgID := fmt.Sprintf("P2_%v_%v", phone, rawTime)

		if isAlreadySent(msgID) { continue }

		newMsgsCount++
		sendWhatsAppMessage(cli, r, msgID, false, 4) // index 4 for msg
	}

	if newMsgsCount == 0 {
		fmt.Println("ℹ️ [P2] No NEW messages found.")
	} else {
		fmt.Printf("🎉 [P2] Processed %d NEW messages!\n", newMsgsCount)
	}
}

// ================= Common WhatsApp Sender =================

func sendWhatsAppMessage(cli *whatsmeow.Client, r []interface{}, msgID string, isBootMsg bool, msgIndex int) {
	rawTime := fmt.Sprintf("%v", r[0])
	countryRaw := fmt.Sprintf("%v", r[1])
	phone := fmt.Sprintf("%v", r[2])
	service := fmt.Sprintf("%v", r[3])
	
	fullMsg := fmt.Sprintf("%v", r[msgIndex])
	fullMsg = html.UnescapeString(fullMsg)
	fullMsg = strings.ReplaceAll(fullMsg, "null", "")
	flatMsg := strings.ReplaceAll(strings.ReplaceAll(fullMsg, "\n", " "), "\r", "")

	if phone == "0" || phone == "" { return }

	cleanCountry := cleanCountryName(countryRaw)
	cFlag, _ := GetCountryWithFlag(cleanCountry)
	otpCode := extractOTP(fullMsg)
	maskedPhone := maskPhoneNumber(phone)

	header := fmt.Sprintf("✨ *%s | %s Message* ⚡\n\n", cFlag, strings.ToUpper(service))
	if isBootMsg {
		header = "🟢 *Bot Active* 🟢\n\n" + header
	}

	messageBody := header +
		fmt.Sprintf("> *Time:* %s\n"+
		"> *Country:* %s %s\n"+
		"   *Number:* *%s*\n"+
		"> *Service:* %s\n"+
		"   *OTP:* *%s*\n\n"+
		"> *Join For Numbers:* \n"+
		"> ¹ https://whatsapp.com/channel/0029VbClXwrATRSmvUg4F43l\n"+
		"*Full Message:*\n"+
		"%s\n\n"+
		"> © Developed by Nothing Is Impossible",
		rawTime, cFlag, cleanCountry, maskedPhone, service, otpCode, flatMsg)

	for _, jidStr := range Config.OTPChannelIDs {
		jid, err := types.ParseJID(jidStr)
		if err != nil { continue }

		_, err = cli.SendMessage(context.Background(), jid, &waProto.Message{
			Conversation: proto.String(strings.TrimSpace(messageBody)),
		})
		
		if err != nil {
			fmt.Printf("❌ [Send Error] %s: %v\n", phone, err)
		} else {
			fmt.Printf("✅ [Sent] OTP for %s to Channel [%s]\n", phone, jidStr)
		}
		time.Sleep(1 * time.Second) 
	}
	markAsSent(msgID)
}

// ================= WhatsApp Events & Handlers =================

func handler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		if !v.Info.IsFromMe {
			handleIDCommand(v)
		}
	case *events.LoggedOut:
		fmt.Println("⚠️ [Warn] Logged out from WhatsApp!")
	case *events.Disconnected:
		fmt.Println("❌ [Error] Disconnected! Reconnecting...")
	case *events.Connected:
		fmt.Println("✅ [Info] Connected to WhatsApp")
	}
}

func handlePairAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, `{"error":"Invalid URL format. Use: /link/pair/NUMBER"}`, 400)
		return
	}

	number := strings.TrimSpace(parts[3])
	number = strings.ReplaceAll(number, "+", "")
	number = strings.ReplaceAll(number, " ", "")
	number = strings.ReplaceAll(number, "-", "")

	if len(number) < 10 || len(number) > 15 {
		http.Error(w, `{"error":"Invalid phone number"}`, 400)
		return
	}

	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📱 PAIRING REQUEST: %s\n", number)

	if client != nil && client.IsConnected() {
		client.Disconnect()
		time.Sleep(2 * time.Second)
	}

	newDevice := container.NewDevice()
	tempClient := whatsmeow.NewClient(newDevice, waLog.Stdout("Pairing", "INFO", true))
	tempClient.AddEventHandler(handler)

	err := tempClient.Connect()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Connection failed: %v"}`, err), 500)
		return
	}

	time.Sleep(3 * time.Second)

	code, err := tempClient.PairPhone(
		context.Background(),
		number,
		true,
		whatsmeow.PairClientChrome,
		"Chrome (Linux)",
	)

	if err != nil {
		tempClient.Disconnect()
		http.Error(w, fmt.Sprintf(`{"error":"Pairing failed: %v"}`, err), 500)
		return
	}

	fmt.Printf("✅ Code generated: %s\n", code)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	go func() {
		for i := 0; i < 60; i++ {
			time.Sleep(1 * time.Second)
			if tempClient.Store.ID != nil {
				fmt.Println("✅ Pairing successful!")
				client = tempClient
				return
			}
		}
		tempClient.Disconnect()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"success": "true",
		"code":    code,
		"number":  number,
	})
}

func handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	if client != nil && client.IsConnected() {
		client.Disconnect()
	}

	devices, _ := container.GetAllDevices(context.Background())
	for _, device := range devices {
		device.Delete(context.Background())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"success": "true",
		"message": "Session deleted successfully",
	})
}

func handleIDCommand(evt *events.Message) {
	msgText := ""
	if evt.Message.GetConversation() != "" {
		msgText = evt.Message.GetConversation()
	} else if evt.Message.ExtendedTextMessage != nil {
		msgText = evt.Message.ExtendedTextMessage.GetText()
	}

	if strings.TrimSpace(strings.ToLower(msgText)) == ".id" {
		senderJID := evt.Info.Sender.ToNonAD().String()
		chatJID := evt.Info.Chat.ToNonAD().String()

		response := fmt.Sprintf("👤 *User ID:*\n`%s`\n\n📍 *Chat/Group ID:*\n`%s`", senderJID, chatJID)

		if evt.Message.ExtendedTextMessage != nil && evt.Message.ExtendedTextMessage.ContextInfo != nil {
			quotedID := evt.Message.ExtendedTextMessage.ContextInfo.Participant
			if quotedID != nil {
				cleanQuoted := strings.Split(*quotedID, "@")[0] + "@" + strings.Split(*quotedID, "@")[1]
				cleanQuoted = strings.Split(cleanQuoted, ":")[0]
				response += fmt.Sprintf("\n\n↩️ *Replied ID:*\n`%s`", cleanQuoted)
			}
		}

		if client != nil {
			client.SendMessage(context.Background(), evt.Info.Chat, &waProto.Message{
				Conversation: proto.String(response),
			})
		}
	}
}

// ================= Main Function =================

func main() {
	fmt.Println("🚀 [Init] Starting Kami Bot...")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("✅ Kami Bot is Running! Use /link/pair/NUMBER to pair."))
	})
	
	http.HandleFunc("/link/pair/", handlePairAPI)
	http.HandleFunc("/link/delete", handleDeleteSession)

	go func() {
		addr := "0.0.0.0:" + port
		fmt.Printf("🌐 API Server listening on %s\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			os.Exit(1)
		}
	}()

	initSQLiteDB()
	initClients()
	
	loginToPanel1()
	loginToPanel2()

	dbURL := "file:/app/data/kami_session.db?_foreign_keys=on"
	dbLog := waLog.Stdout("Database", "INFO", true)
	
	var err error
	container, err = sqlstore.New(context.Background(), "sqlite3", dbURL, dbLog)
	if err == nil {
		deviceStore, err := container.GetFirstDevice(context.Background())
		if err == nil {
			client = whatsmeow.NewClient(deviceStore, waLog.Stdout("Client", "INFO", true))
			client.AddEventHandler(handler)

			if client.Store.ID != nil {
				_ = client.Connect()
				fmt.Println("✅ Session restored")
			}
		}
	}

	// ================= Panel 1 Loop (5 Seconds) =================
	go func() {
		for {
			if client != nil && client.IsLoggedIn() {
				checkPanel1OTPs(client)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// ================= Panel 2 Loop (10 Seconds) =================
	go func() {
		for {
			if client != nil && client.IsLoggedIn() {
				checkPanel2OTPs(client)
			}
			time.Sleep(10 * time.Second)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("\n🛑 Shutting down...")
	if client != nil {
		client.Disconnect()
	}
}
