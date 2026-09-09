package easyconnect

import (
	"cmp"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const maximumResponseLength = 8 << 20

func parseServerURL(server string) (*url.URL, error) {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, E.Cause(err, "parse easyconnect server")
	}
	if serverURL.Scheme != "https" || serverURL.Hostname() == "" {
		return nil, E.New("server must be an HTTPS host")
	}
	if serverURL.User != nil {
		return nil, E.New("server must not contain URL user information")
	}
	if serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return nil, E.New("server must not contain a query or fragment")
	}
	serverURL.Path = strings.TrimSuffix(serverURL.Path, "/")
	return serverURL, nil
}

func (c *Client) serverDestination() M.Socksaddr {
	port := cmp.Or(c.serverURL.Port(), "443")
	return M.ParseSocksaddr(net.JoinHostPort(c.serverURL.Hostname(), port))
}

func newHTTPClient(client *Client, tlsConfig *tls.Config) (*http.Client, *http.Transport, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, nil, E.Cause(err, "create easyconnect cookie jar")
	}
	transportTLSConfig := tlsConfig.Clone()
	transportTLSConfig.NextProtos = []string{"http/1.1"}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return client.options.Dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		ForceAttemptHTTP2:  false,
		TLSClientConfig:    transportTLSConfig,
		DisableCompression: true,
	}
	return &http.Client{
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(request *http.Request, previousRequests []*http.Request) error {
			return E.New("unexpected redirect to ", request.URL.Redacted())
		},
	}, transport, nil
}

func (c *Client) endpointURL(path string, query url.Values) string {
	endpoint := *c.serverURL
	endpoint.Path = c.serverURL.Path + path
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (c *Client) requestXML(ctx context.Context, method string, endpoint string, body url.Values) (*xmlElement, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(body.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("User-Agent", "")
	if body != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected HTTP status ", response.Status)
	}
	document, err := parseXMLDocument(io.LimitReader(response.Body, maximumResponseLength))
	if err != nil {
		return nil, err
	}
	return document, nil
}
