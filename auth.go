package easyconnect

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	logoutTimeout   = 10 * time.Second
	twfIDLength     = 16
	defaultLanguage = "en_US"

	// Auth.Result of login_psw.csp, as parseAuthResult reads it.
	authResultSuccess  = 1
	authResultNextAuth = 2

	// resourceListNonce is a hard code magic.
	resourceListNonce = "1234"
)

type webSession struct {
	twfID      string
	parameters tunnelParameters
	resources  []Resource
	hosts      []DNSHost
}

func (c *Client) authenticate(ctx context.Context) (*webSession, error) {
	// The reference client leaves no web connection behind once the tunnel is
	// up, and a gateway that drops idle connections must not fail a later
	// request.
	defer c.httpTransport.CloseIdleConnections()
	authQuery := url.Values{
		"dev":      {c.options.Device},
		"language": {c.options.Language},
		"type":     {"cs"},
	}
	document, err := c.requestXML(ctx, http.MethodGet, c.endpointURL("/por/login_auth.csp", authQuery), nil)
	if err != nil {
		return nil, E.Cause(err, "login_auth.csp")
	}
	err = checkLoginAuthResult(document)
	if err != nil {
		return nil, E.Cause(err, "login_auth.csp")
	}
	_, err = parseTwfID(document)
	if err != nil {
		return nil, E.Cause(err, "login_auth.csp")
	}

	document, err = c.requestXML(ctx, http.MethodPost, c.endpointURL("/por/login_psw.csp", authQuery), url.Values{
		"svpn_name":     {c.options.Username},
		"svpn_password": {c.options.Password},
	})
	if err != nil {
		return nil, E.Cause(err, "login_psw.csp")
	}
	err = checkLoginPasswordResult(document)
	if err != nil {
		return nil, E.Cause(err, "login_psw.csp")
	}
	twfID, err := parseTwfID(document)
	if err != nil {
		return nil, E.Cause(err, "login_psw.csp")
	}

	document, err = c.requestXML(ctx, http.MethodGet, c.endpointURL("/por/conf.csp", nil), nil)
	if err != nil {
		return nil, E.Cause(err, "conf.csp")
	}
	parameters, err := parseTunnelParameters(document)
	if err != nil {
		return nil, E.Cause(err, "conf.csp")
	}
	session := &webSession{twfID: twfID, parameters: parameters}
	if c.options.ResourceRoutesDisabled {
		return session, nil
	}
	document, err = c.requestXML(ctx, http.MethodGet, c.endpointURL("/por/rclist.csp", url.Values{"rnd": {resourceListNonce}}), nil)
	if err != nil {
		// The resource list only refines the tunnel routes;
		// a gateway that refuses it still carries traffic.
		c.options.Logger.DebugContext(ctx, "rclist.csp: ", err)
		return session, nil
	}
	records := parseDNSHostRecords(document)
	session.resources = applyDNSHosts(parseResourceList(document), records)
	session.hosts = collectDNSHosts(records)
	session.parameters.dns = mergeAddresses(session.parameters.dns, parseDNSServers(document))
	return session, nil
}

func (c *Client) releaseWebSession(session *webSession) {
	if session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.options.Context), logoutTimeout)
	defer cancel()
	defer c.httpTransport.CloseIdleConnections()
	_, err := c.requestXML(ctx, http.MethodGet, c.endpointURL("/por/logout.csp", nil), nil)
	if err != nil {
		c.options.Logger.DebugContext(ctx, "logout.csp: ", err)
	}
}

func checkLoginAuthResult(document *xmlElement) error {
	imageCode, err := strconv.Atoi(document.text("RndImg"))
	if err != nil {
		return authenticationError(document.text("Message"), "missing RndImg")
	}
	if imageCode == 1 {
		return markTerminal(E.Extend(ErrProtocolNotSupported, "gateway requires an image verification code"))
	}
	return nil
}

func checkLoginPasswordResult(document *xmlElement) error {
	message := document.text("Message")
	result, err := strconv.Atoi(document.text("Result"))
	if err != nil {
		return authenticationError(message, "missing Result")
	}
	switch result {
	case authResultSuccess:
		return nil
	case authResultNextAuth:
		return additionalAuthenticationError(document)
	default:
		return authenticationError(message, "result ", result)
	}
}

func authenticationError(message string, fallback ...any) error {
	if message != "" {
		return E.Extend(ErrAuthenticationFailed, strings.TrimSpace(message))
	}
	return E.Extend(ErrAuthenticationFailed, fallback...)
}

func additionalAuthenticationError(document *xmlElement) error {
	if nextService := document.text("NextService"); nextService != "" {
		return markTerminal(E.Extend(ErrProtocolNotSupported, "gateway requires additional authentication: ", nextService))
	}
	return markTerminal(E.Extend(ErrProtocolNotSupported, "gateway requires additional authentication ", document.text("NextAuth")))
}

func parseTwfID(document *xmlElement) (string, error) {
	twfID := document.text("TwfID")
	if twfID == "" {
		return "", E.New("missing TwfID")
	}
	if len(twfID) != twfIDLength {
		return "", E.New("invalid TwfID length ", len(twfID))
	}
	_, err := hex.DecodeString(twfID)
	if err != nil {
		return "", E.Cause(err, "invalid TwfID")
	}
	return twfID, nil
}
