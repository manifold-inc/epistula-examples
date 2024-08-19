package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/itering/subscan/util/ss58"

	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func signMessage(message []byte, public string, private string) string {
	// Signs a message via schnorrkel pub and private keys

	var pubk [32]byte
	data, err := hex.DecodeString(public)
	if err != nil {
		log.Fatalf("Failed to decode public key: %s", err)
	}
	copy(pubk[:], data)

	var prik [32]byte
	data, err = hex.DecodeString(private)
	if err != nil {
		log.Fatalf("Failed to decode private key: %s", err)
	}
	copy(prik[:], data)

	priv := schnorrkel.SecretKey{}
	priv.Decode(prik)
	pub := schnorrkel.PublicKey{}
	pub.Decode(pubk)

	signingCtx := []byte("substrate")
	signingTranscript := schnorrkel.NewSigningContext(signingCtx, message)
	sig, _ := priv.Sign(signingTranscript)
	sigEncode := sig.Encode()
	out := hex.EncodeToString(sigEncode[:])

	return "0x" + out
}

func verifyMessage(message []byte, signature string, public string) bool {
	// Signs a message via schnorrkel pub and private keys
	var pubk [32]byte
	publicKey := ss58.Decode(public, 42)
	data, err := hex.DecodeString(publicKey)
	copy(pubk[:], data)

	pub := schnorrkel.PublicKey{}
	pub.Decode(pubk)
	signingCtx := []byte("substrate")
	verifyTranscript := schnorrkel.NewSigningContext(signingCtx, message)
	sig, err := schnorrkel.NewSignatureFromHex(signature)
	if err != nil {
		log.Printf(err.Error())
	}

	ok, err := pub.Verify(sig, verifyTranscript)
	if err != nil {
		log.Printf(err.Error())
	}
	return ok
}

type Epistula struct {
	Data      any    `json:"data"`
	Nonce     int64  `json:"nonce"`
	SignedBy  string `json:"signed_by"`
	SignedFor string `json:"signed_for"`
}

func main() {
	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Route => handler
	e.POST("/", func(c echo.Context) error {
		sig := c.Request().Header.Get("Body-Signature")
		body, err := io.ReadAll(c.Request().Body)
		if err != nil {
			log.Println(err)
		}
		var req Epistula
		json.Unmarshal(body, &req)
		ok := verifyMessage(body, sig, req.SignedBy)
		return c.String(http.StatusOK, fmt.Sprint(ok))
	})

	// Start server
	e.Logger.Fatal(e.Start(":4001"))
}
