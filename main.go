package main

import (
	"context"
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
	
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *whatsmeow.Client
var container *sqlstore.Container
var mongoColl *mongo.Collection
var isFirstRun = true

var directAPIClient *http.Client

// یہ فنکشن CookieJar کے ساتھ کلائنٹ بنائے گا
func initDirectAPIClient() {
	jar, _ := cookiejar.New(nil)
	directAPIClient = &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
	}
}

// یہ فنکشن پینل پر لاگ ان کر کے کیپچا خود سالو کرے گا
func loginToSMSPanel() bool {
	loginURL := "http://185.2.83.39/ints/login"
	signinURL := "http://185.2.83.39/ints/signin"

	// 1. لاگ ان پیج کھولیں تاکہ کیپچا اور نیا سیشن مل سکے
	resp, err := directAPIClient.Get(loginURL)
	if err != nil {
		fmt.Println("❌ Login Page Fetch Error:", err)
		return false
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(bodyBytes)

	// 2. Regex سے کیپچا نکالیں (What is X + Y = ?)
	re := regexp.MustCompile(`What is (\d+)\s*\+\s*(\d+)\s*=\s*\?`)
	matches := re.FindStringSubmatch(bodyStr)
	
	captchaAnswer := "11" // Fallback
	if len(matches) == 3 {
		num1, _ := strconv.Atoi(matches[1])
		num2, _ := strconv.Atoi(matches[2])
		captchaAnswer = strconv.Itoa(num1 + num2)
	}

	// 3. لاگ ان ریکویسٹ بھیجیں
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
		fmt.Println("❌ Signin Error:", err)
		return false
	}
	defer resp2.Body.Close()

	fmt.Println("✅ Successfully Logged into SMS Panel!")
	return true
}

// یہ فنکشن ڈائریکٹ پینل سے JSON ڈیٹا لائے گا
func fetchDirectOTPData() []interface{} {
	now := time.Now()
	dateStr := now.Format("2006-01-02")
	
	// آج کی ڈیٹ کے حساب سے URL بنائیں
	fetchURL := fmt.Sprintf("http://185.2.83.39/ints/agent/res/data_smscdr.php?fdate1=%s%%2000:00:00&fdate2=%s%%2023:59:59&sEcho=1&iColumns=9&iDisplayStart=0&iDisplayLength=25", dateStr, dateStr)

	req, _ := http.NewRequest("GET", fetchURL, nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36")

	resp, err := directAPIClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// اگر سیشن ایکسپائر ہو گیا ہے (پینل لاگ ان پیج پر ری ڈائریکٹ کر دے)
	if resp.Request.URL.Path == "/ints/login" {
		fmt.Println("⚠️ Session Expired. Re-logging...")
		if loginToSMSPanel() {
			return fetchDirectOTPData() // لاگ ان کے بعد دوبارہ ٹرائی کریں
		}
		return nil
	}

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	
	if data != nil && data["aaData"] != nil {
		return data["aaData"].([]interface{})
	}
	return nil
}

// --- MongoDB Setup ---
func initMongoDB() {
	uri := "mongodb://mongo:ChdVBzAfqsdxgYSlkcyKnNMoEKJnlJlf@yamanote.proxy.rlwy.net:22558"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mClient, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	mongoColl = mClient.Database("kami_otp_db").Collection("sent_otps")
}

func isAlreadySent(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var result bson.M
	err := mongoColl.FindOne(ctx, bson.M{"msg_id": id}).Decode(&result)
	return err == nil
}

func markAsSent(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = mongoColl.InsertOne(ctx, bson.M{"msg_id": id, "at": time.Now()})
}

// --- Helper Functions ---
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

// --- Monitoring Loop ---
func checkOTPs(cli *whatsmeow.Client) {
	if !cli.IsConnected() || !cli.IsLoggedIn() {
		return
	}

	aaData := fetchDirectOTPData()
	if len(aaData) == 0 {
		return
	}

	if isFirstRun {
		for _, row := range aaData {
			r := row.([]interface{})
			msgID := fmt.Sprintf("%v_%v", r[2], r[0])
			if !isAlreadySent(msgID) {
				markAsSent(msgID)
			}
		}
		isFirstRun = false
		return
	}

	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 6 {
			continue
		}

		// JSON Response کے حساب سے انڈیکس میچنگ
		rawTime := fmt.Sprintf("%v", r[0])
		countryRaw := fmt.Sprintf("%v", r[1])
		phone := fmt.Sprintf("%v", r[2])
		service := fmt.Sprintf("%v", r[3])
		fullMsg := fmt.Sprintf("%v", r[5]) // نوٹ: دی گئی JSON میں میسج 5ویں انڈیکس پر ہے

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
			fmt.Printf("✅ [Sent] Direct Panel: %s\n", phone)
		}
	}
}


// Event Handler
// Event Handler
func handler(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		// Check if message is not from self (optional, but good practice)
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


// ================= API ENDPOINTS =================

func handlePairAPI(w http.ResponseWriter, r *http.Request) {
	// Extract number from URL: /link/pair/923027665767
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

	// Disconnect current session
	if client != nil && client.IsConnected() {
		fmt.Println("🔄 Disconnecting old session...")
		client.Disconnect()
		time.Sleep(2 * time.Second)
	}

	// Create new device
	newDevice := container.NewDevice()
	tempClient := whatsmeow.NewClient(newDevice, waLog.Stdout("Pairing", "INFO", true))
	tempClient.AddEventHandler(handler)

	// Connect
	err := tempClient.Connect()
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
		http.Error(w, fmt.Sprintf(`{"error":"Connection failed: %v"}`, err), 500)
		return
	}

	// Wait for stable connection
	time.Sleep(3 * time.Second)

	// Generate pairing code
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

	// Watch for successful pairing
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

	// Return response
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

	// Delete all devices from DB
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

// ... اوپر والے imports اور functions وہی رہیں گے ...

func main() {
	fmt.Println("🚀 [Init] Starting Kami Bot...")

	// 1. Port Setup (Railway Variable)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// 2. HTTP Server (Started in Background Immediately)
	// یہ سب سے پہلے چلائیں گے تاکہ Railway کو فورا Response ملے
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("✅ Kami Bot is Running! Use /link/pair/NUMBER to pair."))
	})
	
	http.HandleFunc("/link/pair/", handlePairAPI)
	http.HandleFunc("/link/delete", handleDeleteSession)

	go func() {
		// IMPORTANT: "0.0.0.0" lagana lazmi hai Railway ke liye
		addr := "0.0.0.0:" + port
		fmt.Printf("🌐 API Server listening on %s\n", addr)
		
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Printf("❌ Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	// 3. Database Connections (After Server Start)
	initMongoDB()
	initDirectAPIClient()
	loginToSMSPanel() // سٹارٹ اپ پر پہلا لاگ ان
	

	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	dbType := "postgres"
	if dbURL == "" {
		fmt.Println("⚠️ DATABASE_URL not found, using SQLite")
		dbURL = "file:kami_session.db?_foreign_keys=on"
		dbType = "sqlite3"
	}

	dbLog := waLog.Stdout("Database", "INFO", true)
	var err error
	container, err = sqlstore.New(context.Background(), dbType, dbURL, dbLog)
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

	// 4. OTP Monitor Loop
	go func() {
		for {
			if client != nil && client.IsLoggedIn() {
				checkOTPs(client)
			}
			time.Sleep(3 * time.Second)
		}
	}()

	// Keep Alive
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("\n🛑 Shutting down...")
	if client != nil {
		client.Disconnect()
	}
}

func handleIDCommand(evt *events.Message) {
	// 1. Get Text Content
	msgText := ""
	if evt.Message.GetConversation() != "" {
		msgText = evt.Message.GetConversation()
	} else if evt.Message.ExtendedTextMessage != nil {
		msgText = evt.Message.ExtendedTextMessage.GetText()
	}

	// 2. Check Command
	if strings.TrimSpace(strings.ToLower(msgText)) == ".id" {
		// Clean JIDs using ToNonAD() to avoid extra device info causing errors
		senderJID := evt.Info.Sender.ToNonAD().String()
		chatJID := evt.Info.Chat.ToNonAD().String()

		// Build Response using Monospace format (` `) to prevent rendering issues
		response := fmt.Sprintf("👤 *User ID:*\n`%s`\n\n📍 *Chat/Group ID:*\n`%s`", senderJID, chatJID)

		// 3. Check for Quoted Message (Reply)
		if evt.Message.ExtendedTextMessage != nil && evt.Message.ExtendedTextMessage.ContextInfo != nil {
			quotedID := evt.Message.ExtendedTextMessage.ContextInfo.Participant
			if quotedID != nil {
				// Clean the quoted ID manually if needed or just print strictly
				cleanQuoted := strings.Split(*quotedID, "@")[0] + "@" + strings.Split(*quotedID, "@")[1]
				cleanQuoted = strings.Split(cleanQuoted, ":")[0] // Ensure no device ID
				response += fmt.Sprintf("\n\n↩️ *Replied ID:*\n`%s`", cleanQuoted)
			}
		}

		// 4. Send Message
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
