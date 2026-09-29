package certificate

import (
	"crypto/x509"
	"encoding/asn1"
)

// extensionNames maps well-known extension OIDs to names.
var extensionNames = map[string]string{
	"2.5.29.9":                "Subject Directory Attributes",
	"2.5.29.14":               "Subject Key Identifier",
	"2.5.29.15":               "Key Usage",
	"2.5.29.16":               "Private Key Usage Period",
	"2.5.29.17":               "Subject Alternative Name",
	"2.5.29.18":               "Issuer Alternative Name",
	"2.5.29.19":               "Basic Constraints",
	"2.5.29.30":               "Name Constraints",
	"2.5.29.31":               "CRL Distribution Points",
	"2.5.29.32":               "Certificate Policies",
	"2.5.29.33":               "Policy Mappings",
	"2.5.29.35":               "Authority Key Identifier",
	"2.5.29.36":               "Policy Constraints",
	"2.5.29.37":               "Extended Key Usage",
	"2.5.29.46":               "Freshest CRL",
	"2.5.29.54":               "Inhibit anyPolicy",
	"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
	"1.3.6.1.5.5.7.1.11":      "Subject Information Access",
	"1.3.6.1.5.5.7.1.24":      "TLS Feature (OCSP Must-Staple)",
	"1.3.6.1.5.5.7.1.3":       "QC Statements",
	"1.3.6.1.4.1.11129.2.4.2": "CT Precertificate SCTs",
	"1.3.6.1.4.1.11129.2.4.3": "CT Precertificate Poison",
	"1.3.6.1.4.1.311.20.2":    "Microsoft Certificate Template Name",
	"1.3.6.1.4.1.311.21.1":    "Microsoft CA Version",
	"1.3.6.1.4.1.311.21.7":    "Microsoft Certificate Template",
	"1.3.6.1.4.1.311.21.10":   "Microsoft Application Policies",
	"2.16.840.1.113730.1.1":   "Netscape Cert Type",
	"2.16.840.1.113730.1.13":  "Netscape Comment",
	"1.3.6.1.5.5.7.48.1.5":    "OCSP No Check",
}

// ExtensionName returns a readable name for an extension OID, or "".
func ExtensionName(oid asn1.ObjectIdentifier) string { return extensionNames[oid.String()] }

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                     "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "E-mail Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

var unknownEKUNames = map[string]string{
	"1.3.6.1.4.1.311.10.3.4":  "Microsoft Encrypted File System",
	"1.3.6.1.4.1.311.20.2.2":  "Microsoft Smart Card Logon",
	"1.3.6.1.5.2.3.5":         "Kerberos KDC",
	"1.3.6.1.5.5.7.3.17":      "IPSec IKE",
	"1.3.6.1.4.1.11129.2.4.4": "CT Precertificate Signing",
	"2.23.133.8.1":            "TCG Endorsement Key Certificate",
}

// ExtKeyUsageName returns a readable EKU name.
func ExtKeyUsageName(u x509.ExtKeyUsage) string {
	if n, ok := extKeyUsageNames[u]; ok {
		return n
	}
	return "unknown"
}

// UnknownExtKeyUsageName names EKU OIDs that crypto/x509 does not model.
func UnknownExtKeyUsageName(oid asn1.ObjectIdentifier) string {
	if n, ok := unknownEKUNames[oid.String()]; ok {
		return n
	}
	return oid.String()
}

// KeyUsageNames returns the names of the set bits.
func KeyUsageNames(ku x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	var out []string
	for _, n := range names {
		if ku&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

var policyNames = map[string]string{
	"2.5.29.32.0":             "anyPolicy",
	"2.23.140.1.1":            "CA/B Forum Extended Validation",
	"2.23.140.1.2.1":          "CA/B Forum Domain Validated",
	"2.23.140.1.2.2":          "CA/B Forum Organization Validated",
	"2.23.140.1.2.3":          "CA/B Forum Individual Validated",
	"2.23.140.1.3":            "CA/B Forum EV Code Signing",
	"2.23.140.1.4.1":          "CA/B Forum Code Signing",
	"2.23.140.1.5.1.1":        "CA/B Forum S/MIME Mailbox Legacy",
	"1.3.6.1.4.1.44947.1.1.1": "ISRG Domain Validated",
}

// PolicyName returns a readable certificate policy name, or "".
func PolicyName(oid string) string { return policyNames[oid] }

var signatureInfo = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA:    "insecure",
	x509.MD5WithRSA:    "insecure",
	x509.SHA1WithRSA:   "deprecated",
	x509.DSAWithSHA1:   "deprecated",
	x509.DSAWithSHA256: "deprecated",
	x509.ECDSAWithSHA1: "deprecated",
}

// SignatureStrength classifies a signature algorithm: modern, deprecated
// (SHA-1, DSA: collision attacks or withdrawn), insecure (MD2/MD5), unknown.
func SignatureStrength(a x509.SignatureAlgorithm) string {
	if s, ok := signatureInfo[a]; ok {
		return s
	}
	if a == x509.UnknownSignatureAlgorithm {
		return "unknown"
	}
	return "modern"
}
