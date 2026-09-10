package bnt

import (
	"encoding/base64"
	"testing"
	"time"
)

// FuzzBntParse 模糊测试Parse入口，喂各种乱码base64字符串给Parse
func FuzzBntParse(f *testing.F) {
	// 种子用例：1个正常token作为基础种子，fuzz会在此基础上变异
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().UTC()
	seedClaims := &RegisteredClaims{
		ID:        "seed-jti-001",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(seedClaims, method)
	seedTokenStr, err := tok.SignedString()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedTokenStr)

	f.Fuzz(func(t *testing.T, tokenStr string) {
		outClaims := &RegisteredClaims{}
		// 只要不panic，返回任意error都是正常；禁止崩溃
		_, _ = Parse(tokenStr, outClaims, method)
	})
}

// FuzzBase64RawBytes 直接对二进制原始token字节模糊测试
func FuzzBntRawBytes(f *testing.F) {
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().UTC()
	seedClaims := &RegisteredClaims{
		ID:        "raw-seed",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(seedClaims, method)
	tokenStr, err := tok.SignedString()
	if err != nil {
		f.Fatal(err)
	}
	rawBytes, _ := base64.StdEncoding.DecodeString(tokenStr)
	f.Add(rawBytes)

	f.Fuzz(func(t *testing.T, raw []byte) {
		// 编码成base64字符串送入Parse
		b64 := base64.StdEncoding.EncodeToString(raw)
		outClaims := &RegisteredClaims{}
		_, _ = Parse(b64, outClaims, method)
	})
}

func FuzzBntSignVerify(f *testing.F) {
	method, err := NewSigningMethodBinaryWithKID(testAESKey, testHMACKey, testKID)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().UTC()
	seedClaims := &RegisteredClaims{
		ID:        "fuzz-sign-verify",
		IssuedAt:  &now,
		ExpiresAt: ptrTime(now.Add(1 * time.Hour)),
		Ttl:       3600,
	}
	tok := NewToken(seedClaims, method)
	seedToken, err := tok.SignedString()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedToken)

	f.Fuzz(func(t *testing.T, tokenStr string) {
		out := &RegisteredClaims{}
		_, _ = Parse(tokenStr, out, method)
	})
}

// # 运行一段时间，自动发现异常
// go test -fuzz=FuzzBntParse -fuzztime=120s
// go test -fuzz=FuzzBntRawBytes -fuzztime=120s
// go test -fuzz=FuzzBntSignVerify -fuzztime=120s
