// Cross-implementation interop harness for the hand-rolled TPM 2.0
// marshalling in obsign-tpm-enroll and obsign-audit-core.
//
// go-tpm (github.com/google/go-tpm, legacy tpm2 package) is an independent
// implementation of the same TCG wire formats, exercised in production
// against real TPM hardware fleets. Agreement with it is evidence that our
// reading of the spec is the spec, not a swtpm-shaped private dialect.
//
// Two modes, driven by the Rust integration test tests/interop_go_tpm.rs:
//
//	decode  — reads JSON {publics: [hex], attests: [hex]} on stdin. Each
//	          TPMT_PUBLIC and TPMS_ATTEST is decoded by go-tpm, re-encoded,
//	          and reported with its computed Name / attested fields. The
//	          Rust side byte-compares the round trip.
//	enroll  — performs a full enrollment ceremony (AK + identity key,
//	          PCR extend, certify, quote) through go-tpm's own marshalling
//	          against the swtpm at -tpm, and emits the raw material as JSON.
//	          The Rust side assembles a KeyAttestation from it and runs
//	          obsign-audit-core's verifier: a foreign encoder, our decoder.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "interop: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: interop decode|enroll [flags]")
	}
	switch os.Args[1] {
	case "decode":
		decodeMode()
	case "enroll":
		enrollMode(os.Args[2:])
	default:
		fatal("unknown mode %q", os.Args[1])
	}
}

// ---------------------------------------------------------------- decode --

type decodeInput struct {
	Publics []string `json:"publics"`
	Attests []string `json:"attests"`
}

type decodedPublic struct {
	Reencoded string `json:"reencoded"`
	Name      string `json:"name"` // be16(nameAlg) || digest
	Type      string `json:"type"`
	Curve     uint16 `json:"curve"`
	Scheme    uint16 `json:"scheme"`
}

type decodedAttest struct {
	Reencoded   string `json:"reencoded"`
	Magic       string `json:"magic"`
	Type        string `json:"type"`
	CertifyName string `json:"certify_name,omitempty"` // be16(alg) || digest
	QuoteBank   uint16 `json:"quote_bank,omitempty"`
	QuotePCRs   []int  `json:"quote_pcrs,omitempty"`
	PCRDigest   string `json:"pcr_digest,omitempty"`
}

func nameHex(n tpm2.Name) string {
	if n.Digest == nil {
		return ""
	}
	b := []byte{byte(uint16(n.Digest.Alg) >> 8), byte(uint16(n.Digest.Alg))}
	return hex.EncodeToString(append(b, n.Digest.Value...))
}

func decodeMode() {
	var in decodeInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fatal("reading input: %v", err)
	}
	out := struct {
		Publics []decodedPublic `json:"publics"`
		Attests []decodedAttest `json:"attests"`
	}{}

	for i, h := range in.Publics {
		raw, err := hex.DecodeString(h)
		if err != nil {
			fatal("public %d: %v", i, err)
		}
		pub, err := tpm2.DecodePublic(raw)
		if err != nil {
			fatal("public %d: go-tpm rejects the TPMT_PUBLIC: %v", i, err)
		}
		re, err := pub.Encode()
		if err != nil {
			fatal("public %d: re-encode: %v", i, err)
		}
		name, err := pub.Name()
		if err != nil {
			fatal("public %d: name: %v", i, err)
		}
		d := decodedPublic{
			Reencoded: hex.EncodeToString(re),
			Name:      nameHex(name),
			Type:      fmt.Sprintf("0x%04X", uint16(pub.Type)),
		}
		if pub.ECCParameters != nil {
			d.Curve = uint16(pub.ECCParameters.CurveID)
			if pub.ECCParameters.Sign != nil {
				d.Scheme = uint16(pub.ECCParameters.Sign.Alg)
			}
		}
		out.Publics = append(out.Publics, d)
	}

	for i, h := range in.Attests {
		raw, err := hex.DecodeString(h)
		if err != nil {
			fatal("attest %d: %v", i, err)
		}
		ad, err := tpm2.DecodeAttestationData(raw)
		if err != nil {
			fatal("attest %d: go-tpm rejects the TPMS_ATTEST: %v", i, err)
		}
		re, err := ad.Encode()
		if err != nil {
			fatal("attest %d: re-encode: %v", i, err)
		}
		d := decodedAttest{
			Reencoded: hex.EncodeToString(re),
			Magic:     fmt.Sprintf("0x%08X", ad.Magic),
			Type:      fmt.Sprintf("0x%04X", uint16(ad.Type)),
		}
		if ad.AttestedCertifyInfo != nil {
			d.CertifyName = nameHex(ad.AttestedCertifyInfo.Name)
		}
		if ad.AttestedQuoteInfo != nil {
			d.QuoteBank = uint16(ad.AttestedQuoteInfo.PCRSelection.Hash)
			d.QuotePCRs = ad.AttestedQuoteInfo.PCRSelection.PCRs
			d.PCRDigest = hex.EncodeToString(ad.AttestedQuoteInfo.PCRDigest)
		}
		out.Attests = append(out.Attests, d)
	}

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fatal("writing output: %v", err)
	}
}

// ---------------------------------------------------------------- enroll --

type enrollOutput struct {
	AkPoint       string `json:"ak_point"`       // 04 || X || Y, hex
	IdentityPub   string `json:"identity_pub"`   // raw TPMT_PUBLIC, hex
	IdentityPoint string `json:"identity_point"` // 04 || X || Y, hex
	Certify       string `json:"certify"`        // attest || r || s, hex
	Quote         string `json:"quote"`          // attest || r || s, hex
	PCRValue      string `json:"pcr_value"`      // SHA-256 bank value, hex
}

func eccTemplate(restricted bool) tpm2.Public {
	props := tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth | tpm2.FlagSign
	if restricted {
		props |= tpm2.FlagRestricted
	}
	return tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: props,
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
		},
	}
}

// point renders ECC coordinates as the verifier's 04 || X || Y form,
// each coordinate left-padded to 32 bytes.
func point(p tpm2.ECPoint) string {
	out := make([]byte, 65)
	out[0] = 0x04
	p.X().FillBytes(out[1:33])
	p.Y().FillBytes(out[33:65])
	return hex.EncodeToString(out)
}

// sig64 renders an ECDSA signature as the verifier's fixed r || s form.
func sig64(sig *tpm2.Signature) ([]byte, error) {
	if sig.ECC == nil {
		return nil, fmt.Errorf("signature is not ECC (alg 0x%04X)", uint16(sig.Alg))
	}
	out := make([]byte, 64)
	sig.ECC.R.FillBytes(out[:32])
	sig.ECC.S.FillBytes(out[32:])
	return out, nil
}

func enrollMode(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	tpmAddr := fs.String("tpm", "", "TPM command socket, host:port")
	pcr := fs.Int("pcr", 16, "PCR index to extend and quote")
	hashHex := fs.String("hash", "", "SHA-256 to extend into the PCR, hex")
	fs.Parse(args)
	digest, err := hex.DecodeString(*hashHex)
	if err != nil || len(digest) != 32 {
		fatal("-hash must be 32 bytes of hex")
	}

	rwc, err := net.Dial("tcp", *tpmAddr)
	if err != nil {
		fatal("connecting to %s: %v", *tpmAddr, err)
	}
	defer rwc.Close()

	// The swtpm the Rust side hands over is already started; a second
	// TPM2_Startup answers TPM_RC_INITIALIZE, which is fine.
	_ = tpm2.Startup(rwc, tpm2.StartupClear)

	ak, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement,
		tpm2.PCRSelection{}, "", "", eccTemplate(true))
	if err != nil {
		fatal("CreatePrimary(AK): %v", err)
	}
	defer tpm2.FlushContext(rwc, ak)

	identity, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner,
		tpm2.PCRSelection{}, "", "", eccTemplate(false))
	if err != nil {
		fatal("CreatePrimary(identity): %v", err)
	}
	defer tpm2.FlushContext(rwc, identity)

	akPub, _, _, err := tpm2.ReadPublic(rwc, ak)
	if err != nil {
		fatal("ReadPublic(AK): %v", err)
	}
	idPub, _, _, err := tpm2.ReadPublic(rwc, identity)
	if err != nil {
		fatal("ReadPublic(identity): %v", err)
	}
	idPubRaw, err := idPub.Encode()
	if err != nil {
		fatal("encoding identity TPMT_PUBLIC: %v", err)
	}

	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(*pcr), tpm2.AlgSHA256, digest, ""); err != nil {
		fatal("PCRExtend: %v", err)
	}
	pcrValue, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		fatal("ReadPCR: %v", err)
	}

	certAttest, certSigRaw, err := tpm2.CertifyEx(rwc, "", "", identity, ak, nil,
		tpm2.SigScheme{Alg: tpm2.AlgNull})
	if err != nil {
		fatal("Certify: %v", err)
	}
	certSig, err := tpm2.DecodeSignature(bytes.NewBuffer(certSigRaw))
	if err != nil {
		fatal("decoding certify signature: %v", err)
	}
	certSig64, err := sig64(certSig)
	if err != nil {
		fatal("certify: %v", err)
	}

	quoteAttest, quoteSig, err := tpm2.Quote(rwc, ak, "", "", nil,
		tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{*pcr}}, tpm2.AlgNull)
	if err != nil {
		fatal("Quote: %v", err)
	}
	quoteSig64, err := sig64(quoteSig)
	if err != nil {
		fatal("quote: %v", err)
	}

	out := enrollOutput{
		AkPoint:       point(akPub.ECCParameters.Point),
		IdentityPub:   hex.EncodeToString(idPubRaw),
		IdentityPoint: point(idPub.ECCParameters.Point),
		Certify:       hex.EncodeToString(append(certAttest, certSig64...)),
		Quote:         hex.EncodeToString(append(quoteAttest, quoteSig64...)),
		PCRValue:      hex.EncodeToString(pcrValue),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fatal("writing output: %v", err)
	}
}
