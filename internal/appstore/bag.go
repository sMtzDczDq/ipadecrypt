package appstore

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type bagResult struct {
	URLBag struct {
		AuthEndpoint         string `plist:"authenticateAccount,omitempty"`
		UpdateProduct        string `plist:"updateProduct,omitempty"`
		SAPSetupEndpoint     string `plist:"sign-sap-setup,omitempty"`
		SAPSetupCertEndpoint string `plist:"sign-sap-setup-cert,omitempty"`
		SAPVersion           string `plist:"sign-sap-version,omitempty"`
	} `plist:"urlBag,omitempty"`
	AuthEndpoint string `plist:"authenticateAccount,omitempty"`
}

// bag fetches the App Store bag.xml and returns the current SAP signing config:
// the authenticate endpoint to sign against plus the setup/certificate endpoints
// and version used to establish the machine-signing session during Login.
func (c *Client) bag() (SAPConfig, error) {
	out, err := c.fetchBag()
	if err != nil {
		return SAPConfig{}, err
	}

	config := SAPConfig{
		AuthEndpoint:   out.URLBag.AuthEndpoint,
		SetupURL:       out.URLBag.SAPSetupEndpoint,
		CertificateURL: out.URLBag.SAPSetupCertEndpoint,
	}

	version, err := strconv.ParseUint(out.URLBag.SAPVersion, 10, 32)
	if err != nil {
		return SAPConfig{}, fmt.Errorf("bag: invalid SAP version %q: %w", out.URLBag.SAPVersion, err)
	}

	config.Version = uint32(version)

	if err := validateSAPConfig(config); err != nil {
		return SAPConfig{}, fmt.Errorf("bag: %w", err)
	}

	return config, nil
}

// fetchBag fetches and decodes the App Store bag.xml without the SAP-specific
// validation that bag() applies, so download fallbacks can read the download
// endpoints exactly as Login reads the auth endpoints.
func (c *Client) fetchBag() (bagResult, error) {
	g, err := guid()
	if err != nil {
		return bagResult{}, err
	}

	url := fmt.Sprintf("https://%s%s?guid=%s", initDomain, initPath, g)

	var out bagResult

	res, err := c.send(http.MethodGet, url, map[string]string{"Accept": "application/xml"}, nil, nil, formatXML, &out)
	if err != nil {
		return bagResult{}, fmt.Errorf("bag: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return bagResult{}, fmt.Errorf("bag: status %d", res.StatusCode)
	}

	return out, nil
}

// updateProductEndpoint returns the updateProduct endpoint advertised in the
// bag. The legacy download endpoint no longer returns packages published on or
// after 2026-09-01; those are only served by this endpoint.
func (c *Client) updateProductEndpoint() (string, error) {
	out, err := c.fetchBag()
	if err != nil {
		return "", err
	}

	if ep := out.URLBag.UpdateProduct; ep != "" {
		return ep, nil
	}

	return "", errors.New("bag: no updateProduct endpoint")
}

// validateSAPConfig checks that the SAP endpoints are well-formed HTTPS URLs,
// that the authenticate endpoint targets the signed MZFinance authenticate path,
// and that the SAP version is one this build supports.
func validateSAPConfig(config SAPConfig) error {
	if err := validateAuthenticationEndpoint(config.AuthEndpoint); err != nil {
		return err
	}

	for name, endpoint := range map[string]string{
		"SAP setup":      config.SetupURL,
		"SAP setup cert": config.CertificateURL,
	} {
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("invalid %s endpoint %q", name, endpoint)
		}
	}

	if config.Version != supportedSAPVersion {
		return fmt.Errorf("unsupported SAP version %d", config.Version)
	}

	return nil
}

// validateAuthenticationEndpoint ensures the authenticate endpoint is the signed
// MZFinance authenticate path, optionally on a per-pod buy subdomain.
func validateAuthenticationEndpoint(endpoint string) error {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("invalid authentication endpoint %q", endpoint)
	}

	host := strings.ToLower(parsed.Hostname())
	if host != "buy."+iTunesDomain && !strings.HasSuffix(host, "-buy."+iTunesDomain) {
		return fmt.Errorf("unsupported authentication endpoint %q", endpoint)
	}

	if parsed.Path != PrivateAppStoreAPIPathAuth {
		return fmt.Errorf("unsupported authentication endpoint %q", endpoint)
	}

	return nil
}
