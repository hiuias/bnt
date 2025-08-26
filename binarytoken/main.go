package binarytoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// 常量定义（安全参数）
const (
	AESKeyLen     = 32 // AES-256 密钥长度（必须32字节）
	GCMNonceLen   = 12 // GCM推荐Nonce长度
	HMACSigLen    = 32 // HMAC-SHA256 签名长度
	MinHMACKeyLen = 16 // HMAC密钥最小长度
)

// 用于验证Base64字符串的正则表达式
var base64Regex = regexp.MustCompile(`^[A-Za-z0-9+/]+(={0,2})$`)

// Claims 定义claims接口，所有自定义claims需实现此接口
type Claims interface {
	Valid() error
}

// RegisteredClaims 包含标准的声明字段
type RegisteredClaims struct {
	ExpiresAt *time.Time `json:"exp,omitempty"` // 过期时间
	IssuedAt  *time.Time `json:"iat,omitempty"` // 签发时间
	NotBefore *time.Time `json:"nbf,omitempty"` // 生效时间
	Issuer    string     `json:"iss,omitempty"` // 签发者
	Subject   string     `json:"sub,omitempty"` // 主题
	ID        string     `json:"jti,omitempty"` // Token ID
}

// Valid 验证标准声明
func (c *RegisteredClaims) Valid() error {
	now := time.Now().UTC()

	// 验证过期时间
	if c.ExpiresAt != nil && !c.ExpiresAt.IsZero() {
		expTime := *c.ExpiresAt
		if expTime.Before(now) {
			return errors.New("token is expired")
		}
	}

	// 验证生效时间
	if c.NotBefore != nil && !c.NotBefore.IsZero() {
		nbfTime := *c.NotBefore
		if nbfTime.After(now) {
			return errors.New("token is not valid yet")
		}
	}

	// 验证签发时间
	if c.IssuedAt != nil && !c.IssuedAt.IsZero() {
		iatTime := *c.IssuedAt
		if iatTime.After(now) {
			return errors.New("token issued in the future")
		}
	}

	return nil
}

// SigningMethod 定义签名方法接口
type SigningMethod interface {
	Alg() string
	Sign(payload []byte) ([]byte, error)
	Verify(payload, signature []byte) error
}

// SigningMethodBinary 二进制签名实现
type SigningMethodBinary struct {
	aesKey  []byte
	hmacKey []byte
}

// NewSigningMethodBinary 创建新的二进制签名方法
func NewSigningMethodBinary(aesKey, hmacKey []byte) (*SigningMethodBinary, error) {
	if len(aesKey) != AESKeyLen {
		return nil, fmt.Errorf("aes key must be %d bytes (AES-256)", AESKeyLen)
	}
	if len(hmacKey) < MinHMACKeyLen {
		return nil, fmt.Errorf("hmac key too short (min %d bytes)", MinHMACKeyLen)
	}
	return &SigningMethodBinary{
		aesKey:  aesKey,
		hmacKey: hmacKey,
	}, nil
}

// Alg 返回算法名称
func (s *SigningMethodBinary) Alg() string {
	return "BINARY-HS256"
}

// Sign 对payload进行签名，返回二进制token
func (s *SigningMethodBinary) Sign(payload []byte) ([]byte, error) {
	// 步骤1: AES-GCM加密payload
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, GCMNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 加密，结果包含nonce
	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	// 步骤2: HMAC-SHA256签名
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err := mac.Write(encryptedPayload); err != nil {
		return nil, fmt.Errorf("failed to write to hmac: %w", err)
	}
	signature := mac.Sum(nil)

	// 步骤3: 拼接二进制流（加密payload + 签名）
	return append(encryptedPayload, signature...), nil
}

// Verify 验证签名
func (s *SigningMethodBinary) Verify(payload, signature []byte) error {
	// 步骤1: 检查长度
	if len(signature) < HMACSigLen {
		return errors.New("invalid token: too short")
	}

	// 步骤2: 分离加密payload和签名
	encryptedPayload := signature[:len(signature)-HMACSigLen]
	receivedSig := signature[len(signature)-HMACSigLen:]

	// 步骤3: 验证HMAC签名
	mac := hmac.New(sha256.New, s.hmacKey)
	if _, err := mac.Write(encryptedPayload); err != nil {
		return fmt.Errorf("failed to write to hmac: %w", err)
	}
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(receivedSig, expectedSig) {
		return errors.New("invalid token: signature mismatch")
	}

	// 步骤4: 解密并验证payload
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(encryptedPayload) < GCMNonceLen {
		return errors.New("invalid token: encrypted payload too short")
	}

	nonce := encryptedPayload[:GCMNonceLen]
	ciphertext := encryptedPayload[GCMNonceLen:]

	// 解密
	decryptedPayload, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// 检查解密后的payload是否与原始payload一致
	if !hmac.Equal(decryptedPayload, payload) {
		return errors.New("invalid token: payload mismatch")
	}

	return nil
}

// Token 表示一个令牌对象
type Token struct {
	Claims Claims
	Method SigningMethod
}

// NewToken 创建一个新的Token
func NewToken(claims Claims, method SigningMethod) *Token {
	return &Token{
		Claims: claims,
		Method: method,
	}
}

// SignedString 生成签名后的token字符串，确保使用标准Base64编码
func (t *Token) SignedString() (string, error) {
	// 将claims序列化为JSON
	claimsBytes, err := json.Marshal(t.Claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims failed: %w", err)
	}
	fmt.Println(claimsBytes)
	// 签名
	signedBytes, err := t.Method.Sign(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}
	fmt.Println(" 签名>>>", signedBytes)
	// 使用标准Base64编码，确保URL安全
	encoded := base64.StdEncoding.EncodeToString(signedBytes)
	fmt.Println(" Base64>>>", encoded)
	// 验证生成的Base64字符串是否符合标准
	if !base64Regex.MatchString(encoded) {
		return "", errors.New("generated token contains invalid base64 characters")
	}

	return encoded, nil
}

// Parse 解析并验证token字符串
func Parse(tokenStr string, claims Claims, method SigningMethod) (*Token, error) {
	// 验证输入的Base64格式
	if !base64Regex.MatchString(tokenStr) {
		return nil, errors.New("invalid base64 characters in token")
	}

	// Base64解码
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// 提取加密的payload部分
	if len(tokenBytes) < HMACSigLen {
		return nil, errors.New("invalid token: too short")
	}
	encryptedPayload := tokenBytes[:len(tokenBytes)-HMACSigLen]

	// 解密payload
	binaryMethod, ok := method.(*SigningMethodBinary)
	if !ok {
		return nil, errors.New("unsupported signing method")
	}

	block, err := aes.NewCipher(binaryMethod.aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(encryptedPayload) < GCMNonceLen {
		return nil, errors.New("invalid token: encrypted payload too short")
	}

	nonce := encryptedPayload[:GCMNonceLen]
	ciphertext := encryptedPayload[GCMNonceLen:]

	decryptedBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// 反序列化到claims
	if err := json.Unmarshal(decryptedBytes, claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims failed: %w", err)
	}

	// 验证claims
	if err := claims.Valid(); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// 验证签名
	if err := method.Verify(decryptedBytes, tokenBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 创建并返回token对象
	return &Token{
		Claims: claims,
		Method: method,
	}, nil
}

// 示例：自定义Claims
type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	RegisteredClaims
}

// Valid 验证自定义claims
func (uc *UserClaims) Valid() error {
	// 先验证标准声明
	if err := uc.RegisteredClaims.Valid(); err != nil {
		return err
	}

	// 验证自定义字段
	if uc.UserID == "" {
		return errors.New("user_id is required")
	}

	if uc.Username == "" {
		return errors.New("username is required")
	}

	return nil
}
