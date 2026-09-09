package easyconnect

import (
	"cmp"
	"crypto/tls"
	"crypto/x509"

	E "github.com/sagernet/sing/common/exceptions"
)

// buildClientTLS configures the web authentication transport. The data plane
// never runs a TLS stack, so this only covers the /por/*.csp endpoints.
func buildClientTLS(options ClientOptions) (*tls.Config, error) {
	tlsOptions := options.TLSConfig
	err := tlsOptions.CertificateAuthority.Validate("certificate authority")
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{}
	if tlsOptions.Config != nil {
		tlsConfig = tlsOptions.Config.Clone()
	}
	tlsConfig.ServerName = cmp.Or(tlsOptions.ServerName, tlsConfig.ServerName)
	tlsConfig.InsecureSkipVerify = cmp.Or(tlsOptions.Insecure, tlsConfig.InsecureSkipVerify)
	tlsConfig.MinVersion = tls.VersionTLS10
	if tlsOptions.SystemTrustDisabled && tlsConfig.RootCAs == nil {
		tlsConfig.RootCAs = x509.NewCertPool()
	}
	if tlsOptions.CertificateAuthority.IsSet() {
		certificateAuthority, loadErr := loadMaterial(tlsOptions.CertificateAuthority)
		if loadErr != nil {
			return nil, E.Cause(loadErr, "load TLS certificate authority")
		}
		rootCAs := tlsConfig.RootCAs
		switch {
		case rootCAs != nil:
			rootCAs = rootCAs.Clone()
		case tlsOptions.SystemTrustDisabled:
			rootCAs = x509.NewCertPool()
		default:
			rootCAs, err = x509.SystemCertPool()
			if err != nil {
				return nil, E.Cause(err, "load system certificate authorities")
			}
		}
		if !rootCAs.AppendCertsFromPEM(certificateAuthority) {
			return nil, E.Extend(ErrInvalidTLSMaterial, "certificate authority")
		}
		tlsConfig.RootCAs = rootCAs
	}
	return tlsConfig, nil
}
