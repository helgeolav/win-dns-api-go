package main

import (
	"bitbucket.org/HelgeOlav/jwtauthrequest/jwtauthapi"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
)

var jwt *jwtauthapi.ClientConfig

// validateToken confirms if the passed token is valid, returns true if token is valid
func validateToken(req *http.Request) error {
	if req == nil {
		return errors.New("nil request passed")
	}
	// find token from http.Request
	var token string
	if keys, ok := req.URL.Query()[jwt.TokenName]; ok {
		if len(keys) > 0 {
			token = keys[0]
		}
	} else {
		token = req.Header.Get(jwt.TokenName)
		if len(jwt.TrimPrefix) > 0 {
			token = strings.TrimPrefix(token, jwt.TrimPrefix)
		}
	}
	// validate token
	err := jwt.ValidateJWT(token)
	if err != nil {
		log.Println(err, token)
	}
	return err
}

// DoDNSSet Set
func DoDNSSet(w http.ResponseWriter, r *http.Request) {
	// check JWT
	{
		err := validateToken(r)
		if err != nil {
			respondWithJSON(w, http.StatusForbidden, map[string]string{"message": err.Error()})
			return
		}
	}
	vars := mux.Vars(r)
	zoneName, dnsType, nodeName, ipAddress := vars["zoneName"], vars["dnsType"], vars["nodeName"], vars["ipAddress"]

	// Validate DNS Type
	if dnsType != "A" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "You specified an invalid record type ('" + dnsType + "'). Currently, only the 'A' (alias) record type is supported.  e.g. /dns/my.zone/A/.."})
		return
	}

	// Validate DNS Type
	var validZoneName = regexp.MustCompile(`[^A-Za-z0-9\.-]+`)

	if validZoneName.MatchString(zoneName) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid zone name ('" + zoneName + "'). Zone names can only contain letters, numbers, dashes (-), and dots (.)."})
		return
	}

	// Validate Node Name
	var validNodeName = regexp.MustCompile(`[^A-Za-z0-9\.-]+`)

	if validNodeName.MatchString(nodeName) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid node name ('" + nodeName + "'). Node names can only contain letters, numbers, dashes (-), and dots (.)."})
		return
	}

	// Validate Ip Address
	var validIPAddress = regexp.MustCompile(`^(([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)\.){3}([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)$`)

	if !validIPAddress.MatchString(ipAddress) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid IP address ('" + ipAddress + "'). Currently, only IPv4 addresses are accepted."})
		return
	}

	dnsCmdDeleteRecord := exec.Command("cmd", "/C", "dnscmd /recorddelete "+zoneName+" "+nodeName+" "+dnsType+" /f")

	if err := dnsCmdDeleteRecord.Run(); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	dnsAddDeleteRecord := exec.Command("cmd", "/C", "dnscmd /recordadd "+zoneName+" "+nodeName+" "+dnsType+" "+ipAddress)

	if err := dnsAddDeleteRecord.Run(); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "The alias ('A') record '" + nodeName + "." + zoneName + "' was successfully updated to '" + ipAddress + "'."})
}

// DoDNSRemove Remove
func DoDNSRemove(w http.ResponseWriter, r *http.Request) {
	// check JWT
	{
		err := validateToken(r)
		if err != nil {
			respondWithJSON(w, http.StatusForbidden, map[string]string{"message": err.Error()})
			return
		}
	}
	vars := mux.Vars(r)
	zoneName, dnsType, nodeName := vars["zoneName"], vars["dnsType"], vars["nodeName"]

	// Validate DNS Type
	if dnsType != "A" {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "You specified an invalid record type ('" + dnsType + "'). Currently, only the 'A' (alias) record type is supported.  e.g. /dns/my.zone/A/.."})
		return
	}

	// Validate DNS Type
	var validZoneName = regexp.MustCompile(`[^A-Za-z0-9\.-]+`)

	if validZoneName.MatchString(zoneName) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid zone name ('" + zoneName + "'). Zone names can only contain letters, numbers, dashes (-), and dots (.)."})
		return
	}

	// Validate Node Name
	var validNodeName = regexp.MustCompile(`[^A-Za-z0-9\.-]+`)

	if validNodeName.MatchString(nodeName) {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid node name ('" + nodeName + "'). Node names can only contain letters, numbers, dashes (-), and dots (.)."})
		return
	}

	dnsCmdDeleteRecord := exec.Command("cmd", "/C", "dnscmd /recorddelete "+zoneName+" "+nodeName+" "+dnsType+" /f")

	if err := dnsCmdDeleteRecord.Run(); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	respondWithJSON(w, http.StatusAccepted, map[string]string{"message": "The alias ('A') record '" + nodeName + "." + zoneName + "' was successfully removed."})
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusBadRequest, map[string]string{"message": "Could not get the requested route."})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

const (
	serverPort = 3111
)

func main() {
	// load jwt config
	var err error
	jwt, err = jwtauthapi.LoadJsonFromFile("config.json")
	if err != nil {
		log.Println("Could not load config.json from current directoy, using defaults")
		var myKeyAsByte = []byte("mysharedsecret")
		tf := jwtauthapi.TokenFactory{
			HMAC:       myKeyAsByte,
			Issuer:     "win-dns-api-go",
			ExpireTime: 60 * 60 * 24,
			Audience:   "win-dns-api-go",
			Extras:     nil,
		}
		tmpJwt := tf.GetClientConfig()
		jwt = &tmpJwt
		jwt.TokenName = "token"
		token, err := tf.Issue()
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Debug token:", token)
	}
	// init
	err = jwt.Init()
	if err != nil {
		log.Fatalln(err)
	}
	// start HTTP server
	r := mux.NewRouter()
	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	r.Methods("GET").Path("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondWithJSON(w, http.StatusOK, map[string]string{"message": "Welcome to Win DNS API Go"})
	})

	r.Methods(http.MethodGet).Path("/dns/{zoneName}/{dnsType}/{nodeName}/set/{ipAddress}").HandlerFunc(DoDNSSet)

	r.Methods(http.MethodGet).Path("/dns/{zoneName}/{dnsType}/{nodeName}/remove").HandlerFunc(DoDNSRemove)
	r.Methods(http.MethodDelete).Path("/dns/{zoneName}/{dnsType}/{nodeName}").HandlerFunc(DoDNSRemove)

	fmt.Printf("Listening on port %d.\n", serverPort)

	// Start HTTP Server
	if err := http.ListenAndServe(
		fmt.Sprintf(":%d", serverPort),
		r,
	); err != nil {
		log.Fatal(err)
	}
}
