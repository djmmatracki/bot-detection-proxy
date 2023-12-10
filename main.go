package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"gopkg.in/yaml.v3"
)

var threatMap = sync.Map{}

type BotDetectorRequest struct {
	RemoteIP              string            `json:"remote_ip"`
	Content               []string          `json:"content"`
	Headers               map[string]string `json:"headers"`
	ConnectionTime        time.Time         `json:"connection_time"`
	ConnectionRequestNum  uint64            `json:"connection_request_number"`
	IsTLS                 bool              `json:"is_tls"`
	UserAgent             string            `json:"user_agent"`
	TLSVersion            uint16            `json:"tls_version"`
	TLSHandshakeComplete  bool              `json:"tls_handshake_complete"`
	TLSDidResume          bool              `json:"tls_did_resume"`
	TLSCipherSuite        uint16            `json:"tls_cipher_suite"`
	TLSNegotiatedProtocol string            `json:"tls_negotiated_protocol"`
}

type BotDetectorResponse struct {
	Threat float64 `json:"threat"`
}

type JsonKeys struct {
	Keys []string `yaml:"jsonKeys"`
}

func getHeadersMap(ctx *fasthttp.RequestCtx) map[string]string {
	keys := ctx.Request.Header.PeekKeys()
	headers := make(map[string]string)
	for _, key := range keys {
		headers[string(key)] = string(ctx.Request.Header.Peek(string(key)))
	}
	return headers
}

func getRequestContent(jsonKeys []string, body []byte) []string {
	var data interface{}
	result := make([]string, 0)

	if len(body) == 0 {
		return result
	}

	// Unmarshal the JSON into an interface
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return result
	}

	// Recursively search for keys
	for _, key := range jsonKeys {
		keys := strings.Split(key, ":")
		result = append(result, findValue(keys, data)...)
	}

	return result
}

func findValue(keys []string, data interface{}) []string {
	var result []string

	// Convert the current data to a map if possible
	currentMap, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	// If there's only one key, return the value
	if len(keys) == 1 {
		if val, exists := currentMap[keys[0]]; exists {
			result = append(result, fmt.Sprintf("%v", val))
		}
		return result
	}

	// If there are nested keys, recurse
	nextKey := keys[0]
	remainingKeys := keys[1:]
	if nextData, exists := currentMap[nextKey]; exists {
		return findValue(remainingKeys, nextData)
	}

	return result
}

func processData(ctx *fasthttp.RequestCtx, botDetectorHost, targetHost string, jsonKeys []string) {
	var tlsVersion, tlsCipherSuite uint16
	var tlsHandshakeComplete, tlsDidResume bool
	var tlsNegotiatedProtocol string
	tlsConnState := ctx.TLSConnectionState()
	if tlsConnState != nil {
		tlsVersion = tlsConnState.Version
		tlsHandshakeComplete = tlsConnState.HandshakeComplete
		tlsDidResume = tlsConnState.DidResume
		tlsCipherSuite = tlsConnState.CipherSuite
		tlsNegotiatedProtocol = tlsConnState.NegotiatedProtocol
	}
	externalIP := ctx.RemoteIP().String()
	userAgent := string(ctx.UserAgent())

	botDetectorRequest := BotDetectorRequest{
		RemoteIP:              externalIP,
		Content:               getRequestContent(jsonKeys, ctx.Request.Body()),
		Headers:               getHeadersMap(ctx),
		ConnectionTime:        ctx.ConnTime(),
		ConnectionRequestNum:  ctx.ConnRequestNum(),
		IsTLS:                 ctx.IsTLS(),
		UserAgent:             userAgent,
		TLSVersion:            tlsVersion,
		TLSHandshakeComplete:  tlsHandshakeComplete,
		TLSDidResume:          tlsDidResume,
		TLSCipherSuite:        tlsCipherSuite,
		TLSNegotiatedProtocol: tlsNegotiatedProtocol,
	}
	reqBody, err := json.Marshal(&botDetectorRequest)
	if err != nil {
		log.Println("error while marshaling bot detector request")
		return
	}
	detectThreatPath, err := url.JoinPath(botDetectorHost, "threat")
	if err != nil {
		log.Println("error joining threat path")
		return
	}
	request, err := http.NewRequest(
		http.MethodPost,
		detectThreatPath,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		log.Println("error creating request")
		return
	}
	client := http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println("error sending request to bot-detector")
		return
	}
	resBody, err := io.ReadAll(response.Body)
	if err != nil {
		log.Println("error while reading response")
		return
	}
	if response.StatusCode != fasthttp.StatusOK {
		log.Printf("error while processing data by bot detector: %s", resBody)
		return
	}
	var botDetectRes BotDetectorResponse
	err = json.Unmarshal(resBody, &botDetectRes)
	if err != nil {
		log.Println("error while unmarshaling response")
		return
	}
	log.Printf("setting client IP '%s' threat to %f, target host: %s",
		externalIP,
		botDetectRes.Threat,
		targetHost,
	)
	threatMap.Store(externalIP, botDetectRes.Threat)
}

func lookupThreat(host, sessionID string) float64 {
	threat, ok := threatMap.Load(sessionID)
	if !ok {
		return 0.0
	}
	return threat.(float64)
}

func formatRequestHandler(backendHost string) fasthttp.RequestHandler {
	backendURL, err := url.Parse(backendHost)
	if err != nil {
		log.Fatalf("Error parsing backend URL: %s", err)
		return nil
	}
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	return fasthttpadaptor.NewFastHTTPHandler(proxy)
}

func handleRequest(ctx *fasthttp.RequestCtx, frontendHost, backendHost fasthttp.RequestHandler, isFrontendAppHost bool) {
	if isFrontendAppHost {
		frontendHost(ctx)
		return
	}
	backendHost(ctx)
}

func main() {
	viper.AddConfigPath("/config")
	viper.AddConfigPath(".")
	viper.SetConfigName("app")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("got error when loading config %v", err)
		return
	}
	botThreashold := viper.GetFloat64("BOT_THRESHOLD")
	backendURL := viper.GetString("BACKEND_URL")
	frontendURL := viper.GetString("FRONTEND_URL")
	frontendHostname := viper.GetString("FRONTEND_HOSTNAME")
	botDetectorHost := viper.GetString("BOT_DETECTOR_HOST")
	jsonKeysConfigPath := viper.GetString("CONTENT_JSON_KEYS_PATH")
	if err != nil {
		log.Fatalf("error while reading bot detected template: %v", err)
		return
	}
	jsonKeysYamlContent, err := os.ReadFile(jsonKeysConfigPath)
	if err != nil {
		log.Fatalf("error while reading json keys yaml file: %v", err)
		return
	}
	var keys JsonKeys
	err = yaml.Unmarshal(jsonKeysYamlContent, &keys)
	if err != nil {
		log.Fatalf("error while unmarshaling yaml file: %v", err)
		return
	}
	backendHost := formatRequestHandler(backendURL)
	frontendHost := formatRequestHandler(frontendURL)

	proxyReq := func(ctx *fasthttp.RequestCtx) {
		hostHeader := string(ctx.Request.Header.Peek("Host"))
		isFrontendAppHost := hostHeader == frontendHostname
		clientIP := ctx.RemoteIP().String()
		if clientIP == "" {
			ctx.Response.SetStatusCode(fasthttp.StatusForbidden)
			return
		}
		if lookupThreat(hostHeader, clientIP) > botThreashold {
			ctx.Response.SetStatusCode(fasthttp.StatusForbidden)
			return
		}
		go processData(ctx, botDetectorHost, hostHeader, keys.Keys)
		handleRequest(ctx, frontendHost, backendHost, isFrontendAppHost)
	}

	log.Println("Starting reverse proxy server on :8000...")
	if err := fasthttp.ListenAndServeTLS(":8000", "/config/fullchain.pem", "/config/privkey.pem", proxyReq); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
		return
	}
}
