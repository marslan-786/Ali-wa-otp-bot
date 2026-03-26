package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
var otpDB *sql.DB // نیا SQLite DB کنکشن OTPs کا ریکارڈ رکھنے کے لیے
var isFirstRun = true
var directAPIClient *http.Client

// ================= HTTP کلائنٹ اور لاگ ان لاجک =================

func initDirectAPIClient() {
	jar, _ := cookiejar.New(nil)
	directAPIClient = &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
	}
}

func loginToSMSPanel() bool {
	fmt.Println("🔄 [Auth] Attempting to login to SMS Panel...")
	loginURL := "http://185.2.83.39/ints/login"
	signinURL := "http://185.2.83.39/ints/signin"

	resp, err := directAPIClient.Get(loginURL)
	if err != nil {
		fmt.Println("❌ [Auth] Login Page Fetch Error:", err)
		return false
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(bodyBytes)

	re := regexp.MustCompile(`What is (\d+)\s*\+\s*(\d+)\s*=\s*\?`)
	matches := re.FindStringSubmatch(bodyStr)
	
	captchaAnswer := "11"
	if len(matches) == 3 {
		num1, _ := strconv.Atoi(matches[1])
		num2, _ := strconv.Atoi(matches[2])
		captchaAnswer = strconv.Itoa(num1 + num2)
		fmt.Printf("🧠 [Auth] Captcha Solved: %s + %s = %s\n", matches[1], matches[2], captchaAnswer)
	} else {
		fmt.Println("⚠️ [Auth] Captcha not found, using fallback answer.")
	}

	formData := url.Values{}
	formData.Set("username", "opxali")
	formData.Set("password", "opxali00")
	formData.Set("capt", captchaAnswer)

	req, _ := http.NewRequest("POST", signinURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36")
	req.Header.Set("Referer", loginURL)

	resp2, err := directAPIClient.Do(req)
	if err != nil {
		fmt.Println("❌ [Auth] Signin Error:", err)
		return false
	}
	defer resp2.Body.Close()

	fmt.Println("✅ [Auth] Successfully Logged into SMS Panel & Session Saved!")
	return true
}

func fetchDirectOTPData() ([]interface{}, bool) {
	now := time.Now()
	dateStr := now.Format("2006-01-02")
	
	fetchURL := fmt.Sprintf("http://185.2.83.39/ints/agent/res/data_smscdr.php?fdate1=%s%%2000:00:00&fdate2=%s%%2023:59:59&sEcho=1&iColumns=9&iDisplayStart=0&iDisplayLength=25", dateStr, dateStr)

	req, _ := http.NewRequest("GET", fetchURL, nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36")

	resp, err := directAPIClient.Do(req)
	if err != nil {
		fmt.Printf("❌ [API] Network Error: %v\n", err)
		return nil, false // false means error / expired
	}
	defer resp.Body.Close()

	if resp.Request.URL.Path == "/ints/login" || resp.StatusCode != http.StatusOK {
		return nil, false // Session Expired
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Println("❌ [API] Failed to parse JSON. Possible session expiration.")
		return nil, false
	}
	
	if data != nil && data["aaData"] != nil {
		return data["aaData"].([]interface{}), true
	}
	return nil, true // Successfully fetched, but array is totally empty
}

// ================= SQLite ڈیٹا بیس Setup =================

func initSQLiteDB() {
	var err error
	// Database connection for OTP history
	otpDB, err = sql.Open("sqlite3", "file:kami_session.db?_foreign_keys=on")
	if err != nil {
		panic(fmt.Sprintf("❌ Failed to open SQLite DB: %v", err))
	}

	// Create table if not exists
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
	_, err := otpDB.Exec(query, id)
	if err != nil {
		fmt.Printf("⚠️ [DB] Failed to save msg_id %s: %v\n", id, err)
	}
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

// ================= Monitoring Loop =================

func checkOTPs(cli *whatsmeow.Client) {
	if !cli.IsConnected() || !cli.IsLoggedIn() {
		return
	}

	fmt.Println("📡 [API] Calling SMS API...")
	aaData, success := fetchDirectOTPData()
	
	if !success {
		fmt.Println("⚠️ [API] Session Expired or No Data from Server. Triggering Re-login...")
		if loginToSMSPanel() {
			fmt.Println("✅ [Auth] Re-login successful. Will resume fetching in next cycle.")
		}
		return
	}

	if len(aaData) == 0 {
		fmt.Println("ℹ️ [API] API called successfully, but no new messages found.")
		return
	}

	fmt.Printf("📥 [API] Data received: %d rows found. Processing...\n", len(aaData))

	if isFirstRun {
		fmt.Println("🚀 [Boot] First run detected, caching old messages to avoid spamming...")
		for _, row := range aaData {
			r := row.([]interface{})
			msgID := fmt.Sprintf("%v_%v", r[2], r[0])
			if !isAlreadySent(msgID) {
				markAsSent(msgID)
			}
		}
		isFirstRun = false
		fmt.Println("✅ [Boot] Old messages cached.")
		return
	}

	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 6 {
			continue
		}

		rawTime := fmt.Sprintf("%v", r[0])
		countryRaw := fmt.Sprintf("%v", r[1])
		phone := fmt.Sprintf("%v", r[2])
		service := fmt.Sprintf("%v", r[3])
		fullMsg := fmt.Sprintf("%v", r[5]) 

		if phone == "0" || phone == "" {
			continue
		}

		msgID := fmt.Sprintf("%v_%v", phone, rawTime)

		if !isAlreadySent(msgID) {
			cleanCountry := cleanCountryName(countryRaw)
			cFlag, _ := GetCountryWithFlag(cleanCountry)
			otpCode := extractOTP(fullMsg)
			maskedPhone := maskPhoneNumber(phone)
			flatMsg := strings.ReplaceAll(strings.ReplaceAll(fullMsg, "\n", " "), "\r", "")

			messageBody := fmt.Sprintf("✨ *%s | %s Message* ⚡\n\n"+
				"> *Time:* %s\n"+
				"> *Country:* %s %s\n"+
				"   *Number:* *%s*\n"+
				"> *Service:* %s\n"+
				"   *OTP:* *%s*\n\n"+
				"> *Join For Numbers:* \n"+
				"> ¹ https://chat.whatsapp.com/EbaJKbt5J2T6pgENIeFFht\n"+
				"*Full Message:*\n"+
				"%s\n\n"+
				"> © Developed by Nothing Is Impossible",
				cFlag, strings.ToUpper(service),
				rawTime, cFlag, cleanCountry, maskedPhone, service, otpCode, flatMsg)

			for _, jidStr := range Config.OTPChannelIDs {
				jid, _ := types.ParseJID(jidStr)
				cli.SendMessage(context.Background(), jid, &waProto.Message{
					Conversation: proto.String(strings.TrimSpace(messageBody)),
				})
				time.Sleep(1 * time.Second)
			}
			markAsSent(msgID)
			fmt.Printf("📤 [Sent] OTP Forwarded to WhatsApp for: %s\n", phone)
		}
	}
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
		fmt.Println("🔄 Disconnecting old session...")
		client.Disconnect()
		time.Sleep(2 * time.Second)
	}

	newDevice := container.NewDevice()
	tempClient := whatsmeow.NewClient(newDevice, waLog.Stdout("Pairing", "INFO", true))
	tempClient.AddEventHandler(handler)

	err := tempClient.Connect()
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
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
		fmt.Printf("❌ Pairing failed: %v\n", err)
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
		fmt.Println("❌ Pairing timeout")
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
	fmt.Println("\n🗑️ DELETE SESSION REQUEST")

	if client != nil && client.IsConnected() {
		client.Disconnect()
		fmt.Println("✅ Client disconnected")
	}

	devices, _ := container.GetAllDevices(context.Background())
	for _, device := range devices {
		err := device.Delete(context.Background())
		if err != nil {
			fmt.Printf("⚠️ Failed to delete device: %v\n", err)
		}
	}

	fmt.Println("✅ All sessions deleted")

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
			_, err := client.SendMessage(context.Background(), evt.Info.Chat, &waProto.Message{
				Conversation: proto.String(response),
			})
			if err != nil {
				fmt.Printf("❌ Failed to send ID: %v\n", err)
			}
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
			fmt.Printf("❌ Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	initSQLiteDB()
	initDirectAPIClient()
	loginToSMSPanel() 

	dbURL := "file:kami_session.db?_foreign_keys=on"
	dbLog := waLog.Stdout("Database", "INFO", true)
	
	var err error
	container, err = sqlstore.New(context.Background(), "sqlite3", dbURL, dbLog)
	if err != nil {
		fmt.Printf("❌ DB Connection Error: %v\n", err)
	} else {
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

	// 5 Second Monitor Loop
	go func() {
		for {
			if client != nil && client.IsLoggedIn() {
				checkOTPs(client)
			} else {
				fmt.Println("⏳ [Wait] WhatsApp not connected yet. Waiting...")
			}
			time.Sleep(5 * time.Second)
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
