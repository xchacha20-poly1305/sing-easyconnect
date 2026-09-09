package easyconnect

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const confDocument = `<?xml version="1.0" encoding="utf-8"?>
<Conf>
	<Htp enable="1" auto="1" param="7|0|1|100|100" port="4433" mtu="1400"/>
	<L3VPN iptunDns="10.1.1.1" iptunDnsBak="0.0.0.0"/>
	<Other login_name="user" sslctx="%s" svpnlanaddr="10.1.253.13" deviceversion="M7.6.8R2"/>
	<SSLCipherSuite>
		<EC>AES128-SHA</EC>
		<TCP>RC4-SHA</TCP>
	</SSLCipherSuite>
	<SSLEigenvalue>
		<TCP>TCPP</TCP>
		<L3VPN>L3IP</L3VPN>
	</SSLEigenvalue>
</Conf>`

func testSSLContext(session string) string {
	sslContext := make([]byte, sslContextLength)
	copy(sslContext, "0123456789abcdef0123456789abcdef")
	copy(sslContext[sslContextSessionOffset:], session)
	return hex.EncodeToString(sslContext)
}

func parseXMLString(t *testing.T, document string) *xmlElement {
	t.Helper()
	parsed, err := parseXMLDocument(strings.NewReader(document))
	require.NoError(t, err)
	return parsed
}

func testConfDocument(t *testing.T, session string) *xmlElement {
	t.Helper()
	return parseXMLString(t, fmt.Sprintf(confDocument, testSSLContext(session)))
}

func TestParseTunnelParameters(t *testing.T) {
	t.Parallel()
	parameters, err := parseTunnelParameters(testConfDocument(t, "fedcba9876543210"))
	require.NoError(t, err)
	require.Equal(t, tunnelParameters{
		session:         mustSessionID(t, "fedcba9876543210"),
		assignedAddress: netip.MustParseAddr("10.1.253.13"),
		tunnelPort:      4433,
		mtu:             1400,
		dns:             []netip.Addr{netip.MustParseAddr("10.1.1.1")},
	}, parameters)
}

func TestParseTunnelParametersRejectsShortSSLContext(t *testing.T) {
	t.Parallel()
	_, err := parseTunnelParameters(parseXMLString(t, `<Conf><Other sslctx="00112233"/></Conf>`))
	require.ErrorContains(t, err, "invalid sslctx length")
}

func TestScopedElementLookup(t *testing.T) {
	t.Parallel()
	document := testConfDocument(t, "fedcba9876543210")
	require.Equal(t, "RC4-SHA", document.element("SSLCipherSuite").text("TCP"))
	require.Equal(t, "TCPP", document.element("SSLEigenvalue").text("TCP"))
}

func TestCheckLoginAuthResult(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		document string
		wantErr  error
	}{
		{
			name:     "no image code",
			document: `<Auth><ErrorCode>1</ErrorCode><RndImg>0</RndImg><Message>login auth success</Message></Auth>`,
		},
		{
			// The reference client never reads ErrorCode here.
			name:     "unexpected error code",
			document: `<Auth><ErrorCode>0</ErrorCode><RndImg>0</RndImg></Auth>`,
		},
		{
			name:     "image code required",
			document: `<Auth><RndImg>1</RndImg></Auth>`,
			wantErr:  ErrProtocolNotSupported,
		},
		{
			name:     "missing image code",
			document: `<Auth><ErrorCode>1</ErrorCode></Auth>`,
			wantErr:  ErrAuthenticationFailed,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := checkLoginAuthResult(parseXMLString(t, testCase.document))
			if testCase.wantErr != nil {
				require.ErrorIs(t, err, testCase.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCheckLoginPasswordResult(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name         string
		document     string
		wantErr      error
		wantTerminal bool
	}{
		{
			name:     "success",
			document: `<Auth><Result>1</Result><ErrorCode>1</ErrorCode><pwpErrorCode>0</pwpErrorCode></Auth>`,
		},
		{
			name:     "rejected",
			document: `<Auth><Result>0</Result><Message>invalid password</Message></Auth>`,
			wantErr:  ErrAuthenticationFailed,
		},
		{
			name:     "missing result",
			document: `<Auth><ErrorCode>20113</ErrorCode><Message>invalid device</Message></Auth>`,
			wantErr:  ErrAuthenticationFailed,
		},
		{
			name:         "next authentication factor",
			document:     `<Auth><Result>2</Result><NextAuth>2</NextAuth><NextService>sms</NextService></Auth>`,
			wantErr:      ErrProtocolNotSupported,
			wantTerminal: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := checkLoginPasswordResult(parseXMLString(t, testCase.document))
			if testCase.wantErr != nil {
				require.ErrorIs(t, err, testCase.wantErr)
				if testCase.wantTerminal {
					var terminal *TerminalError
					require.ErrorAs(t, err, &terminal)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestParseTwfID(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		document string
		want     string
		wantErr  string
	}{
		{
			name:     "valid",
			document: `<Auth><TwfID>1d1731cb9fce86f7</TwfID></Auth>`,
			want:     "1d1731cb9fce86f7",
		},
		{
			name:     "too short",
			document: `<Auth><TwfID>1d17</TwfID></Auth>`,
			wantErr:  "invalid TwfID length",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			twfID, err := parseTwfID(parseXMLString(t, testCase.document))
			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, twfID)
		})
	}
}

func TestParseResourceList(t *testing.T) {
	t.Parallel()
	resources := parseResourceList(parseXMLString(t, `<Resource><Rcs>`+
		`<Rc id="1" name="range" host="192.0.2.96~192.0.2.127" port="1~65535"/>`+
		`<Rc id="2" name="mixed" host="http://app.example.edu/path;192.0.2.20;192.0.2.30:8080/login" port="80~80;80~80;8080~8080"/>`+
		`<Rc id="3" name="empty" host="" port=""/>`+
		`</Rcs></Resource>`))
	require.Equal(t, []Resource{
		{
			ID:   "1",
			Name: "range",
			Entries: []ResourceEntry{{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.96/27")},
				Ports:    PortRange{Start: 1, End: 65535},
			}},
		},
		{
			ID:   "2",
			Name: "mixed",
			Entries: []ResourceEntry{
				{Domain: "app.example.edu", Ports: PortRange{Start: 80, End: 80}},
				{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.20/32")}, Ports: PortRange{Start: 80, End: 80}},
				{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.30/32")}, Ports: PortRange{Start: 8080, End: 8080}},
			},
		},
	}, resources)
}

func TestAddressRangePrefixes(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		start    string
		end      string
		prefixes []netip.Prefix
	}{
		{"single address", "10.0.0.1", "10.0.0.1", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}},
		{"aligned octet", "10.0.0.0", "10.0.0.255", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		{"split range", "10.0.0.1", "10.0.0.6", []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/32"),
			netip.MustParsePrefix("10.0.0.2/31"),
			netip.MustParsePrefix("10.0.0.4/31"),
			netip.MustParsePrefix("10.0.0.6/32"),
		}},
		{"whole internet", "0.0.0.0", "255.255.255.255", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{"reversed", "10.0.0.5", "10.0.0.1", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.prefixes, addressRangePrefixes(
				netip.MustParseAddr(testCase.start),
				netip.MustParseAddr(testCase.end),
			))
		})
	}
}

func TestBuildTunnelConfiguration(t *testing.T) {
	t.Parallel()
	parameters := tunnelParameters{dns: []netip.Addr{netip.MustParseAddr("10.1.1.1")}}
	resources := []Resource{
		{Entries: []ResourceEntry{
			{Domain: "b.example.edu"},
			{Domain: "a.example.edu", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}},
		}},
		{Entries: []ResourceEntry{
			{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32"), netip.MustParsePrefix("192.168.0.0/24")}},
		}},
	}
	require.Equal(t, TunnelConfiguration{
		MTU:       1400,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.1.183.174/32")},
		Routes: []TunnelRoute{
			{Prefix: netip.MustParsePrefix("10.1.0.0/16")},
			{Prefix: netip.MustParsePrefix("192.0.2.10/32")},
			{Prefix: netip.MustParsePrefix("192.168.0.0/24")},
		},
		DNS: []netip.Addr{netip.MustParseAddr("10.1.1.1")},
		Hosts: []DNSHost{{
			Domain:    "portal.example.edu",
			Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		}},
		SearchDomains: []string{"a.example.edu", "b.example.edu", "portal.example.edu"},
		Resources:     resources,
	}, buildTunnelConfiguration(parameters, resources, []DNSHost{{
		Domain:    "portal.example.edu",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}}, netip.MustParseAddr("10.1.183.174"), 1400))
}

func TestParseDNSHosts(t *testing.T) {
	t.Parallel()
	document := parseXMLString(t, `<Resource><Rcs>`+
		`<Rc id="3" name="portal" host="portal.example.edu" port="443~443"/>`+
		`<Rc id="2" name="mixed" host="http://app.example.edu/path" port="80~80"/>`+
		`</Rcs>`+
		`<Dns dnsserver="192.0.2.53;0.0.0.0" data="3:portal.example.edu:192.0.2.10;3:portal.example.edu:192.0.2.10;2:app.example.edu:192.0.2.20;2:192.0.2.20:192.0.2.20;bad;1:missing-ip"/>`+
		`</Resource>`)
	records := parseDNSHostRecords(document)
	require.Equal(t, []dnsHostRecord{
		{resourceID: "3", domain: "portal.example.edu", address: netip.MustParseAddr("192.0.2.10")},
		{resourceID: "3", domain: "portal.example.edu", address: netip.MustParseAddr("192.0.2.10")},
		{resourceID: "2", domain: "app.example.edu", address: netip.MustParseAddr("192.0.2.20")},
	}, records)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.53")}, parseDNSServers(document))
	require.Equal(t, []DNSHost{{
		Domain:    "app.example.edu",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
	}, {
		Domain:    "portal.example.edu",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}}, collectDNSHosts(records))

	resources := applyDNSHosts(parseResourceList(document), records)
	require.Equal(t, []Resource{
		{
			ID:   "3",
			Name: "portal",
			Entries: []ResourceEntry{{
				Domain:   "portal.example.edu",
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")},
				Ports:    PortRange{Start: 443, End: 443},
			}},
		},
		{
			ID:   "2",
			Name: "mixed",
			Entries: []ResourceEntry{{
				Domain:   "app.example.edu",
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.20/32")},
				Ports:    PortRange{Start: 80, End: 80},
			}},
		},
	}, resources)

	filter := newResourceFilter(resources, nil)
	require.True(t, filter.permits(testDatagram(netip.MustParseAddr("192.0.2.10"), 6, 443)))
	require.False(t, filter.permits(testDatagram(netip.MustParseAddr("192.0.2.10"), 6, 80)))
	require.True(t, filter.permits(testDatagram(netip.MustParseAddr("192.0.2.20"), 6, 80)))
}

func TestParseServerURL(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		input    string
		wantHost string
		wantPort string
		wantPath string
		wantErr  string
	}{
		{name: "bare host", input: "vpn.example.edu", wantHost: "vpn.example.edu"},
		{name: "http rejected", input: "http://vpn.example.edu", wantErr: "server must be an HTTPS host"},
		{name: "https with port", input: "https://vpn.example.edu:4433/", wantHost: "vpn.example.edu:4433", wantPort: "4433"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			serverURL, err := parseServerURL(testCase.input)
			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.wantHost, serverURL.Host)
			require.Equal(t, testCase.wantPort, serverURL.Port())
			require.Equal(t, testCase.wantPath, serverURL.Path)
		})
	}
}
