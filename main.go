package main

import (
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
	"sync"
	"syscall"
	"time"

	"github.com/biter777/countries"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nyaruka/phonenumbers"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

var (
	client    *whatsmeow.Client
	container *sqlstore.Container
	otpDB     *sql.DB
	dbMutex   sync.Mutex // کانکرنٹ ڈیٹا بیس رائٹ کو ہینڈل کرنے کے لیے
)

// ================= پینل 1 (SMS Hadi) کے ویری ایبلز =================
var isFirstRunPanel1 = true
var currentSessKeyPanel1 string

// ================= پینل 3 (Time SMS) کے ویری ایبلز =================
var isFirstRunPanel3 = true
var currentSessKeyPanel3 string

// ================= API (Number Panel) کے ویری ایبلز =================
var isFirstRunAPI = true

// ================= الگ الگ HTTP کلائنٹس =================
var (
	panel1Client *http.Client
	panel3Client *http.Client
	apiClient    *http.Client
)

func initClients() {
	jar1, _ := cookiejar.New(nil)
	panel1Client = &http.Client{Jar: jar1, Timeout: 15 * time.Second}

	jar3, _ := cookiejar.New(nil)
	panel3Client = &http.Client{Jar: jar3, Timeout: 15 * time.Second}

	apiClient = &http.Client{Timeout: 15 * time.Second}
}

// ================= ڈیٹا ٹائپ پروٹیکشن فنکشن =================
// یہ فنکشن null یا غلط ڈیٹا پر کریش ہونے سے بچائے گا
func getString(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// ================= پینل 1 (SMS Hadi) =================

func loginToPanel1() bool {
	fmt.Println("🔄 [Auth-Hadi] Attempting to login to SMS Hadi Panel...")
	loginURL := "http://2.59.169.96/ints/login"
	signinURL := "http://2.59.169.96/ints/signin"
	reportsURL := "http://2.59.169.96/ints/agent/SMSCDRReports"

	resp, err := panel1Client.Get(loginURL)
	if err != nil {
		fmt.Println("❌ [Auth-Hadi] Login Page Fetch Error:", err)
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
	}

	formData := url.Values{}
	formData.Set("username", "opxali")
	formData.Set("password", "opxali12")
	formData.Set("capt", captchaAnswer)

	req, _ := http.NewRequest("POST", signinURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	req.Header.Set("Referer", loginURL)

	resp2, err := panel1Client.Do(req)
	if err != nil {
		fmt.Println("❌ [Auth-Hadi] Signin Error:", err)
		return false
	}
	resp2.Body.Close()

	reqReports, _ := http.NewRequest("GET", reportsURL, nil)
	reqReports.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")

	respReports, err := panel1Client.Do(reqReports)
	if err == nil {
		reportsBody, _ := io.ReadAll(respReports.Body)
		respReports.Body.Close()
		keyRegex := regexp.MustCompile(`sesskey=([a-zA-Z0-9=]+)`)
		keyMatches := keyRegex.FindStringSubmatch(string(reportsBody))
		if len(keyMatches) >= 2 {
			currentSessKeyPanel1 = keyMatches[1]
			fmt.Println("✅ [Auth-Hadi] Successfully Logged in & Session Saved!")
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
	timestamp := strconv.FormatInt(now.UnixNano()/1e6, 10)

	params := url.Values{}
	params.Set("fdate1", dateStr+" 00:00:00")
	params.Set("fdate2", dateStr+" 23:59:59")
	params.Set("frange", "")
	params.Set("fclient", "")
	params.Set("fnum", "")
	params.Set("fcli", "")
	params.Set("fgdate", "")
	params.Set("fgmonth", "")
	params.Set("fgrange", "")
	params.Set("fgclient", "")
	params.Set("fgnumber", "")
	params.Set("fgcli", "")
	params.Set("fg", "0")
	params.Set("sesskey", currentSessKeyPanel1)
	params.Set("sEcho", "2")
	params.Set("iColumns", "9")
	params.Set("sColumns", ",,,,,,,,")
	params.Set("iDisplayStart", "0")
	params.Set("iDisplayLength", "50")
	params.Set("_", timestamp)

	for i := 0; i < 9; i++ {
		idx := strconv.Itoa(i)
		params.Set("mDataProp_"+idx, idx)
		params.Set("sSearch_"+idx, "")
		params.Set("bRegex_"+idx, "false")
		params.Set("bSearchable_"+idx, "true")
		if i == 8 {
			params.Set("bSortable_"+idx, "false")
		} else {
			params.Set("bSortable_"+idx, "true")
		}
	}
	params.Set("sSearch", "")
	params.Set("bRegex", "false")
	params.Set("iSortCol_0", "0")
	params.Set("sSortDir_0", "desc")
	params.Set("iSortingCols", "1")

	fetchURL := "http://2.59.169.96/ints/agent/res/data_smscdr.php?" + params.Encode()

	req, _ := http.NewRequest("GET", fetchURL, nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")

	resp, err := panel1Client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.Request.URL.Path == "/ints/login" || resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false // JSON پارس نہ ہو سکے تو خاموشی سے واپس
	}

	// کریش پروٹیکشن: اگر aaData موجود ہی نہ ہو
	aaDataRaw, exists := data["aaData"]
	if !exists || aaDataRaw == nil {
		return nil, true // ریکویسٹ ٹھیک تھی مگر ڈیٹا خالی تھا
	}

	aaData, ok := aaDataRaw.([]interface{})
	if !ok {
		return nil, false // ڈیٹا غلط فارمیٹ میں ہے
	}

	return aaData, true
}

// ================= پینل 3 (Time SMS) =================

func loginToPanel3() bool {
	fmt.Println("🔄 [Auth-TimeSMS] Attempting to login to Time SMS Panel...")
	loginURL := "https://timesms.org/login"
	signinURL := "https://timesms.org/signin"
	reportsURL := "https://timesms.org/agent/SMSCDRReports"

	resp, err := panel3Client.Get(loginURL)
	if err != nil {
		fmt.Println("❌ [Auth-TimeSMS] Login Page Fetch Error:", err)
		return false
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	re := regexp.MustCompile(`What is (\d+)\s*\+\s*(\d+)\s*=\s*\?`)
	matches := re.FindStringSubmatch(string(bodyBytes))

	captchaAnswer := "10"
	if len(matches) == 3 {
		num1, _ := strconv.Atoi(matches[1])
		num2, _ := strconv.Atoi(matches[2])
		captchaAnswer = strconv.Itoa(num1 + num2)
	}

	formData := url.Values{}
	formData.Set("username", "opxali00")
	formData.Set("password", "opxali12")
	formData.Set("capt", captchaAnswer)

	req, _ := http.NewRequest("POST", signinURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	req.Header.Set("Referer", loginURL)

	resp2, err := panel3Client.Do(req)
	if err != nil {
		fmt.Println("❌ [Auth-TimeSMS] Signin Error:", err)
		return false
	}
	resp2.Body.Close()

	reqReports, _ := http.NewRequest("GET", reportsURL, nil)
	reqReports.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")

	respReports, err := panel3Client.Do(reqReports)
	if err == nil {
		reportsBody, _ := io.ReadAll(respReports.Body)
		respReports.Body.Close()
		keyRegex := regexp.MustCompile(`sesskey=([a-zA-Z0-9=]+)`)
		keyMatches := keyRegex.FindStringSubmatch(string(reportsBody))
		if len(keyMatches) >= 2 {
			currentSessKeyPanel3 = keyMatches[1]
			fmt.Println("✅ [Auth-TimeSMS] Successfully Logged in & Session Saved!")
			return true
		}
	}
	return false
}

func fetchPanel3Data() ([]interface{}, bool) {
	if currentSessKeyPanel3 == "" {
		return nil, false
	}

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	timestamp := strconv.FormatInt(now.UnixNano()/1e6, 10)

	params := url.Values{}
	params.Set("fdate1", dateStr+" 00:00:00")
	params.Set("fdate2", dateStr+" 23:59:59")
	params.Set("frange", "")
	params.Set("fclient", "")
	params.Set("fnum", "")
	params.Set("fcli", "")
	params.Set("fgdate", "")
	params.Set("fgmonth", "")
	params.Set("fgrange", "")
	params.Set("fgclient", "")
	params.Set("fgnumber", "")
	params.Set("fgcli", "")
	params.Set("fg", "0")
	params.Set("sesskey", currentSessKeyPanel3)
	params.Set("sEcho", "1")
	params.Set("iColumns", "9")
	params.Set("sColumns", ",,,,,,,,")
	params.Set("iDisplayStart", "0")
	params.Set("iDisplayLength", "25")
	params.Set("_", timestamp)

	for i := 0; i < 9; i++ {
		idx := strconv.Itoa(i)
		params.Set("mDataProp_"+idx, idx)
		params.Set("sSearch_"+idx, "")
		params.Set("bRegex_"+idx, "false")
		params.Set("bSearchable_"+idx, "true")
		if i == 8 {
			params.Set("bSortable_"+idx, "false")
		} else {
			params.Set("bSortable_"+idx, "true")
		}
	}
	params.Set("sSearch", "")
	params.Set("bRegex", "false")
	params.Set("iSortCol_0", "0")
	params.Set("sSortDir_0", "desc")
	params.Set("iSortingCols", "1")

	fetchURL := "https://timesms.org/agent/res/data_smscdr.php?" + params.Encode()

	req, _ := http.NewRequest("GET", fetchURL, nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")

	resp, err := panel3Client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.Request.URL.Path == "/login" || resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false
	}

	// کریش پروٹیکشن: اگر aaData موجود ہی نہ ہو
	aaDataRaw, exists := data["aaData"]
	if !exists || aaDataRaw == nil {
		return nil, true // ریکویسٹ ٹھیک تھی مگر ڈیٹا خالی تھا
	}

	aaData, ok := aaDataRaw.([]interface{})
	if !ok {
		return nil, false
	}

	return aaData, true
}

// ================= API 2 (Number Panel API Direct) =================

func fetchNumberPanelAPI() ([]interface{}, bool) {
	now := time.Now()
	dateStr := now.Format("2006-01-02")
	timestamp := strconv.FormatInt(now.UnixNano()/1e6, 10)

	token := "R1dSSkdBUzRzhHFSf4SMh2FsUVyIZYpiU5GNYkp4aHNVUVVleJSRSA=="
	fetchURL := fmt.Sprintf("http://147.135.212.197/crapi/st/viewstats?token=%s&dt1=%s%%2000:00:00&dt2=%s%%2023:59:59&records=50&_=%s", token, dateStr, dateStr, timestamp)

	req, _ := http.NewRequest("GET", fetchURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false // JSON کا فارمیٹ غلط ہو تو خاموشی سے اگنور کرے گا
	}

	var interfaceData []interface{}
	for _, rowStr := range data {
		var rowInterface []interface{}
		for _, val := range rowStr {
			rowInterface = append(rowInterface, val)
		}
		interfaceData = append(interfaceData, rowInterface)
	}

	return interfaceData, true
}

// ================= Country Extractor =================

func getCountryFromPhone(phone string) string {
	if !strings.HasPrefix(phone, "+") {
		phone = "+" + phone
	}
	num, err := phonenumbers.Parse(phone, "")
	if err != nil {
		return "Unknown"
	}
	region := phonenumbers.GetRegionCodeForNumber(num)
	c := countries.ByName(region)
	if c != countries.Unknown {
		return c.Info().Name
	}
	return region
}

// ================= SQLite ڈیٹا بیس Setup =================

func initSQLiteDB() {
	var err error
	otpDB, err = sql.Open("sqlite3", "file:/app/data/kami.db?_foreign_keys=on")
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
	dbMutex.Lock()
	defer dbMutex.Unlock()

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sent_otps WHERE msg_id = ?)`
	err := otpDB.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func markAsSent(id string) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

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
	if name == "" || name == "Unknown" {
		return "Unknown"
	}
	parts := strings.Fields(strings.Split(name, "-")[0])
	if len(parts) > 0 {
		return parts[0]
	}
	return "Unknown"
}

// ================= Monitoring Loop (Panel 1 - SMS Hadi) =================

func checkPanel1OTPs(cli *whatsmeow.Client) {
	aaData, success := fetchPanel1Data()

	if !success {
		fmt.Println("⚠️ [Hadi] Session Expired. Triggering Re-login...")
		loginToPanel1()
		return
	}

	if len(aaData) == 0 {
		return
	}

	if isFirstRunPanel1 {
		fmt.Println("🚀 [Hadi-Boot] Caching old messages...")
		for i, row := range aaData {
			r, ok := row.([]interface{})
			if !ok || len(r) < 6 { continue }

			rawTime := getString(r[0])
			rangeStr := getString(r[1])
			phone := getString(r[2])
			service := getString(r[3])
			fullMsg := getString(r[5])
			msgID := fmt.Sprintf("H_%v_%v", phone, rawTime)

			if i == 0 {
				sendWhatsAppMessage(cli, rawTime, rangeStr, phone, service, fullMsg, msgID, true, "H")
			}
			markAsSent(msgID)
		}
		isFirstRunPanel1 = false
		return
	}

	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 6 { continue }

		rawTime := getString(r[0])
		rangeStr := getString(r[1])
		phone := getString(r[2])
		service := getString(r[3])
		fullMsg := getString(r[5])
		msgID := fmt.Sprintf("H_%v_%v", phone, rawTime)

		if isAlreadySent(msgID) { continue }

		sendWhatsAppMessage(cli, rawTime, rangeStr, phone, service, fullMsg, msgID, false, "H")
	}
}

// ================= Monitoring Loop (Panel 3 - Time SMS) =================

func checkPanel3OTPs(cli *whatsmeow.Client) {
	aaData, success := fetchPanel3Data()

	if !success {
		fmt.Println("⚠️ [TimeSMS] Session Expired. Triggering Re-login...")
		loginToPanel3()
		return
	}

	if len(aaData) == 0 {
		return
	}

	if isFirstRunPanel3 {
		fmt.Println("🚀 [TimeSMS-Boot] Caching old messages...")
		for i, row := range aaData {
			r, ok := row.([]interface{})
			if !ok || len(r) < 6 { continue }

			rawTime := getString(r[0])
			rangeStr := getString(r[1])
			phone := getString(r[2])
			service := getString(r[3])
			fullMsg := getString(r[5])
			msgID := fmt.Sprintf("TS_%v_%v", phone, rawTime)

			if i == 0 {
				sendWhatsAppMessage(cli, rawTime, rangeStr, phone, service, fullMsg, msgID, true, "TS")
			}
			markAsSent(msgID)
		}
		isFirstRunPanel3 = false
		return
	}

	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 6 { continue }

		rawTime := getString(r[0])
		rangeStr := getString(r[1])
		phone := getString(r[2])
		service := getString(r[3])
		fullMsg := getString(r[5])
		msgID := fmt.Sprintf("TS_%v_%v", phone, rawTime)

		if isAlreadySent(msgID) { continue }

		sendWhatsAppMessage(cli, rawTime, rangeStr, phone, service, fullMsg, msgID, false, "TS")
	}
}

// ================= Monitoring Loop (Number Panel API Direct) =================

func checkAPIOTPs(cli *whatsmeow.Client) {
	aaData, success := fetchNumberPanelAPI()

	if !success || len(aaData) == 0 {
		return
	}

	if isFirstRunAPI {
		fmt.Println("🚀 [NP-Boot] Caching old messages...")
		for i, row := range aaData {
			r, ok := row.([]interface{})
			if !ok || len(r) < 4 { continue }

			service := getString(r[0])
			phone := getString(r[1])
			fullMsg := getString(r[2])
			rawTime := getString(r[3])

			countryName := getCountryFromPhone(phone)
			msgID := fmt.Sprintf("NP_%v_%v", phone, rawTime)

			if i == 0 {
				sendWhatsAppMessage(cli, rawTime, countryName, phone, service, fullMsg, msgID, true, "NP")
			}
			markAsSent(msgID)
		}
		isFirstRunAPI = false
		return
	}

	for _, row := range aaData {
		r, ok := row.([]interface{})
		if !ok || len(r) < 4 { continue }

		service := getString(r[0])
		phone := getString(r[1])
		fullMsg := getString(r[2])
		rawTime := getString(r[3])

		countryName := getCountryFromPhone(phone)
		msgID := fmt.Sprintf("NP_%v_%v", phone, rawTime)

		if isAlreadySent(msgID) { continue }

		sendWhatsAppMessage(cli, rawTime, countryName, phone, service, fullMsg, msgID, false, "NP")
	}
}

// ================= Common WhatsApp Sender =================

func sendWhatsAppMessage(cli *whatsmeow.Client, rawTime, countryRaw, phone, service, fullMsg, msgID string, isBootMsg bool, panelSource string) {
	fullMsg = html.UnescapeString(fullMsg)
	fullMsg = strings.ReplaceAll(fullMsg, "null", "")

	reFixN := regexp.MustCompile(`(\d)n([^\d\s])`)
	fullMsg = reFixN.ReplaceAllString(fullMsg, "$1 $2")

	fullMsg = strings.ReplaceAll(fullMsg, "nDont", " Dont")
	fullMsg = strings.ReplaceAll(fullMsg, "nDo ", " Do ")
	fullMsg = strings.ReplaceAll(fullMsg, "nYour", " Your")
	fullMsg = strings.ReplaceAll(fullMsg, "nNe ", " Ne ")
	fullMsg = strings.ReplaceAll(fullMsg, "nلا ", " لا ")

	flatMsg := strings.ReplaceAll(strings.ReplaceAll(fullMsg, "\n", " "), "\r", "")

	if phone == "0" || phone == "" { return }

	cleanCountry := cleanCountryName(countryRaw)
	cFlag, _ := GetCountryWithFlag(cleanCountry)

	otpCode := extractOTP(flatMsg)
	maskedPhone := maskPhoneNumber(phone)

	header := fmt.Sprintf("✨ *%s | %s Message* ⚡ [%s]\n\n", cFlag, strings.ToUpper(service), panelSource)
	if isBootMsg {
		header = "🟢 *Bot Started / Active Check* 🟢\n\n" + header
	}

	messageBody := header +
		fmt.Sprintf("> *Time:* %s\n"+
		"> *Country:* %s %s\n"+
		"   *Number:* *%s*\n"+
		"> *Service:* %s\n"+
		"   *OTP:* *%s*\n\n"+
		"> *Join For Numbers:* \n"+
		"> ¹ https://chat.whatsapp.com/JqerYdpQZyY09LmX6WqFws?mode=gi_t\n"+
		"*Full Message:*\n"+
		"%s\n\n"+
		"> © Developed by Nothing Is Impossible",
		rawTime, cFlag, cleanCountry, maskedPhone, service, otpCode, flatMsg)

	for _, jidStr := range Config.OTPChannelIDs {
		jid, err := types.ParseJID(jidStr)
		if err != nil { continue }

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = cli.SendMessage(ctx, jid, &waProto.Message{
			Conversation: proto.String(strings.TrimSpace(messageBody)),
		})
		cancel()

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
	loginToPanel3()

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

	// ================= Panel 1 Loop (Auto-Heal Enabled) =================
	go func() {
		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("⚠️ [Recovered] Hadi Panel Crash Prevented: %v\n", r)
					}
				}()
				if client != nil && client.IsConnected() && client.IsLoggedIn() {
					checkPanel1OTPs(client)
				}
			}()
			time.Sleep(5 * time.Second)
		}
	}()

	// ================= Panel 3 Loop (Auto-Heal Enabled) =================
	go func() {
		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("⚠️ [Recovered] TimeSMS Panel Crash Prevented: %v\n", r)
					}
				}()
				if client != nil && client.IsConnected() && client.IsLoggedIn() {
					checkPanel3OTPs(client)
				}
			}()
			time.Sleep(5 * time.Second)
		}
	}()

	// ================= API Loop (Auto-Heal Enabled) =================
	go func() {
		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("⚠️ [Recovered] API Panel Crash Prevented: %v\n", r)
					}
				}()
				if client != nil && client.IsConnected() && client.IsLoggedIn() {
					checkAPIOTPs(client)
				}
			}()
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
