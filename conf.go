package easyconnect

import (
	"encoding/hex"
	"net/netip"
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	sslContextLength = 64
	// The session prefix used by every tunnel message sits in the middle of the
	// sslctx blob; ConfManager logs it as svpnsessionId.
	sslContextSessionOffset = 32
)

// tunnelParameters are the pieces of conf.csp the data plane needs.
type tunnelParameters struct {
	session         sessionID
	assignedAddress netip.Addr
	tunnelPort      uint16
	mtu             uint32
	dns             []netip.Addr
}

func parseTunnelParameters(document *xmlElement) (tunnelParameters, error) {
	var parameters tunnelParameters
	other := document.element("Other")
	if other == nil {
		return parameters, E.New("missing Other element")
	}
	sslContext, err := hex.DecodeString(other.attribute("sslctx"))
	if err != nil {
		return parameters, E.Cause(err, "invalid sslctx")
	}
	if len(sslContext) != sslContextLength {
		return parameters, E.New("invalid sslctx length ", len(sslContext))
	}
	parameters.session, err = parseSessionID(string(sslContext[sslContextSessionOffset : sslContextSessionOffset+SessionIDLength]))
	if err != nil {
		return parameters, err
	}
	if address, parseErr := netip.ParseAddr(other.attribute("svpnlanaddr")); parseErr == nil {
		parameters.assignedAddress = address.Unmap()
	}
	htp := document.element("Htp")
	if port, parseErr := strconv.ParseUint(htp.attribute("port"), 10, 16); parseErr == nil {
		parameters.tunnelPort = uint16(port)
	}
	if mtu, parseErr := strconv.ParseUint(htp.attribute("mtu"), 10, 32); parseErr == nil {
		parameters.mtu = uint32(mtu)
	}
	l3vpn := document.element("L3VPN")
	for _, attributeName := range []string{"iptunDns", "iptunDnsBak"} {
		address, parseErr := netip.ParseAddr(l3vpn.attribute(attributeName))
		if parseErr != nil || !address.IsValid() || address.IsUnspecified() {
			continue
		}
		parameters.dns = append(parameters.dns, address.Unmap())
	}
	return parameters, nil
}
