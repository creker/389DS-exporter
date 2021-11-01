// Ozgur Demir <ozgurcd@gmail.com>

package main

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func getStats(server string, startTLS bool, binddn, password string) (DSData, error) {
	u, err := url.ParseRequestURI(server)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := ldap.DialURL(server)
	if err != nil {
		return DSData{}, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	if startTLS {
		if err := conn.StartTLS(&tls.Config{ServerName: u.Hostname()}); err != nil {
			return DSData{}, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if binddn != "" {
		if err := conn.Bind(binddn, password); err != nil {
			return DSData{}, fmt.Errorf("failed to bind: %w", err)
		}
	}

	searchRequest := ldap.NewSearchRequest(
		"cn=snmp, cn=monitor",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectclass=*)",
		nil,
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return DSData{}, fmt.Errorf("failed to search: %w", err)
	}

	var (
		anonymousbinds             string
		unauthbinds                string
		simpleauthbinds            string
		strongauthbinds            string
		bindsecurityerrors         string
		inops                      string
		readops                    string
		compareops                 string
		addentryops                string
		removeentryops             string
		modifyentryops             string
		modifyrdnops               string
		searchops                  string
		onelevelsearchops          string
		wholesubtreesearchops      string
		referrals                  string
		securityerrors             string
		errors                     string
		connections                string
		connectionseq              string
		connectionsinmaxthreads    string
		connectionsmaxthreadscount string
		bytesrecv                  string
		bytessent                  string
		entriesreturned            string
		referralsreturned          string
		cacheentries               string
		cachehits                  string
	)

	entry := sr.Entries[0]
	attributes := entry.Attributes

	for _, attr := range attributes {
		name := string(attr.Name)
		value := attr.Values

		// ignoring unused attributes.
		switch name {
		case "anonymousbinds":
			anonymousbinds = value[0]
		case "unauthbinds":
			unauthbinds = value[0]
		case "simpleauthbinds":
			simpleauthbinds = value[0]
		case "strongauthbinds":
			strongauthbinds = value[0]
		case "bindsecurityerrors":
			bindsecurityerrors = value[0]
		case "inops":
			inops = value[0]
		case "readops":
			readops = value[0]
		case "compareops":
			compareops = value[0]
		case "addentryops":
			addentryops = value[0]
		case "removeentryops":
			removeentryops = value[0]
		case "modifyentryops":
			modifyentryops = value[0]
		case "modifyrdnops":
			modifyrdnops = value[0]
		case "searchops":
			searchops = value[0]
		case "onelevelsearchops":
			onelevelsearchops = value[0]
		case "wholesubtreesearchops":
			wholesubtreesearchops = value[0]
		case "referrals":
			referrals = value[0]
		case "securityerrors":
			securityerrors = value[0]
		case "errors":
			errors = value[0]
		case "connections":
			connections = value[0]
		case "connectionseq":
			connectionseq = value[0]
		case "connectionsinmaxthreads":
			connectionsinmaxthreads = value[0]
		case "connectionsmaxthreadscount":
			connectionsmaxthreadscount = value[0]
		case "bytesrecv":
			bytesrecv = value[0]
		case "bytessent":
			bytessent = value[0]
		case "entriesreturned":
			entriesreturned = value[0]
		case "referralsreturned":
			referralsreturned = value[0]
		case "cacheentries":
			cacheentries = value[0]
		case "cachehits":
			cachehits = value[0]
		default:
			//fmt.Printf("Name: %s, Value: %s\n", name, value)
		}
	}

	anonymousbinds64, err := strconv.ParseFloat(anonymousbinds, 64)
	if err != nil {
		log.WithError(err).Error("invalid anonymousbinds")
		anonymousbinds64 = 0
	}

	unauthbinds64, err := strconv.ParseFloat(unauthbinds, 64)
	if err != nil {
		log.WithError(err).Error("invalid unauthbinds")
		unauthbinds64 = 0
	}

	simpleauthbinds64, err := strconv.ParseFloat(simpleauthbinds, 64)
	if err != nil {
		log.WithError(err).Error("invalid simpleauthbinds")
		simpleauthbinds64 = 0
	}

	strongauthbinds64, err := strconv.ParseFloat(strongauthbinds, 64)
	if err != nil {
		log.WithError(err).Error("invalid strongauthbinds")
		strongauthbinds64 = 0
	}

	bindsecurityerrors64, err := strconv.ParseFloat(bindsecurityerrors, 64)
	if err != nil {
		log.WithError(err).Error("invalid bindsecurityerrors")
		bindsecurityerrors64 = 0
	}

	inops64, err := strconv.ParseFloat(inops, 64)
	if err != nil {
		log.WithError(err).Error("invalid inops")
		inops64 = 0
	}

	readops64, err := strconv.ParseFloat(readops, 64)
	if err != nil {
		log.WithError(err).Error("invalid readops")
		readops64 = 0
	}

	compareops64, err := strconv.ParseFloat(compareops, 64)
	if err != nil {
		log.WithError(err).Error("invalid compareops")
		compareops64 = 0
	}

	addentryops64, err := strconv.ParseFloat(addentryops, 64)
	if err != nil {
		log.WithError(err).Error("invalid addentryops")
		addentryops64 = 0
	}

	removeentryops64, err := strconv.ParseFloat(removeentryops, 64)
	if err != nil {
		log.WithError(err).Error("invalid removeentryops")
		removeentryops64 = 0
	}

	modifyentryops64, err := strconv.ParseFloat(modifyentryops, 64)
	if err != nil {
		log.WithError(err).Error("invalid modifyentryops")
		modifyentryops64 = 0
	}

	modifyrdnops64, err := strconv.ParseFloat(modifyrdnops, 64)
	if err != nil {
		log.WithError(err).Error("invalid modifyrdnops")
		modifyrdnops64 = 0
	}

	searchops64, err := strconv.ParseFloat(searchops, 64)
	if err != nil {
		log.WithError(err).Error("invalid searchops")
		searchops64 = 0
	}

	onelevelsearchops64, err := strconv.ParseFloat(onelevelsearchops, 64)
	if err != nil {
		log.WithError(err).Error("invalid onelevelsearchops")
		onelevelsearchops64 = 0
	}

	wholesubtreesearchops64, err := strconv.ParseFloat(wholesubtreesearchops, 64)
	if err != nil {
		log.WithError(err).Error("invalid wholesubtreesearchops")
		wholesubtreesearchops64 = 0
	}

	referrals64, err := strconv.ParseFloat(referrals, 64)
	if err != nil {
		log.WithError(err).Error("invalid referrals")
		referrals64 = 0
	}

	securityerrors64, err := strconv.ParseFloat(securityerrors, 64)
	if err != nil {
		log.WithError(err).Error("invalid securityerrors")
		securityerrors64 = 0
	}

	errors64, err := strconv.ParseFloat(errors, 64)
	if err != nil {
		log.WithError(err).Error("invalid errors")
		errors64 = 0
	}

	connections64, err := strconv.ParseFloat(connections, 64)
	if err != nil {
		log.WithError(err).Error("invalid connections")
		connections64 = 0
	}

	connectionseq64, err := strconv.ParseFloat(connectionseq, 64)
	if err != nil {
		log.WithError(err).Error("invalid connectionseq")
		connectionseq64 = 0
	}

	connectionsinmaxthreads64, err := strconv.ParseFloat(connectionsinmaxthreads, 64)
	if err != nil {
		log.WithError(err).Error("invalid connectionsinmaxthreads")
		connectionsinmaxthreads64 = 0
	}

	connectionsmaxthreadscount64, err := strconv.ParseFloat(connectionsmaxthreadscount, 64)
	if err != nil {
		log.WithError(err).Error("invalid connectionsmaxthreadscount")
		connectionsmaxthreadscount64 = 0
	}

	bytesrecv64, err := strconv.ParseFloat(bytesrecv, 64)
	if err != nil {
		log.WithError(err).Error("invalid bytesrecv")
		bytesrecv64 = 0
	}

	bytessent64, err := strconv.ParseFloat(bytessent, 64)
	if err != nil {
		log.WithError(err).Error("invalid bytessent")
		bytessent64 = 0
	}

	entriesreturned64, err := strconv.ParseFloat(entriesreturned, 64)
	if err != nil {
		log.WithError(err).Error("invalid entriesreturned")
		entriesreturned64 = 0
	}

	referralsreturned64, err := strconv.ParseFloat(referralsreturned, 64)
	if err != nil {
		log.WithError(err).Error("invalid referralsreturned")
		referralsreturned64 = 0
	}

	cacheentries64, err := strconv.ParseFloat(cacheentries, 64)
	if err != nil {
		log.WithError(err).Error("invalid cacheentries")
		cacheentries64 = 0
	}

	cachehits64, err := strconv.ParseFloat(cachehits, 64)
	if err != nil {
		log.WithError(err).Error("invalid cachehits")
		cachehits64 = 0
	}

	return DSData{
		up:                         1,
		anonymousbinds:             anonymousbinds64,
		unauthbinds:                unauthbinds64,
		simpleauthbinds:            simpleauthbinds64,
		strongauthbinds:            strongauthbinds64,
		bindsecurityerrors:         bindsecurityerrors64,
		inops:                      inops64,
		readops:                    readops64,
		compareops:                 compareops64,
		addentryops:                addentryops64,
		removeentryops:             removeentryops64,
		modifyentryops:             modifyentryops64,
		modifyrdnops:               modifyrdnops64,
		searchops:                  searchops64,
		onelevelsearchops:          onelevelsearchops64,
		wholesubtreesearchops:      wholesubtreesearchops64,
		referrals:                  referrals64,
		securityerrors:             securityerrors64,
		errors:                     errors64,
		connections:                connections64,
		connectionseq:              connectionseq64,
		connectionsinmaxthreads:    connectionsinmaxthreads64,
		connectionsmaxthreadscount: connectionsmaxthreadscount64,
		bytesrecv:                  bytesrecv64,
		bytessent:                  bytessent64,
		entriesreturned:            entriesreturned64,
		referralsreturned:          referralsreturned64,
		cacheentries:               cacheentries64,
		cachehits:                  cachehits64,
	}, nil
}
