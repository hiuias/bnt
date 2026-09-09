package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hiuias/bnt"
)

// ==================== 数据结构 ====================

// UserInfo 用户信息
type UserInfo struct {
	User struct {
		Domain struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"domain"`
		ID   string `json:"id"`
		Name struct {
			Account string `json:"account"`
		} `json:"name"`
	} `json:"user"`
}

// UserClaims 自定义 Claims
type UserClaims struct {
	UserInfo *UserInfo `json:"user_info"`
	bnt.RegisteredClaims
}

// 实现 Refreshable 接口
func (c *UserClaims) Refresh() error {
	return c.RegisteredClaims.Refresh()
}

// ==================== 1. 初始化 ====================

// Init 初始化签名方法
func Init() (bnt.SigningMethod, error) {
	// 测试用固定密钥
	aesKeyStr := "nZ/ShAOj/VFPz+pJ7dxNy9Y6TuWOp/d412sHuLHfSw8="
	hmacKeyStr := "mJT6l4KpRmATxVtXsDTk8fZ8iORGx3Lm8v0fFyPUme8="

	aesKey, err := base64.StdEncoding.DecodeString(aesKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid AES key: %w", err)
	}

	hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid HMAC key: %w", err)
	}

	return bnt.NewSigningMethodBinary(aesKey, hmacKey)
}

// ==================== 2. 生成 Token ====================

// GenerateToken 生成 Token
func GenerateToken(method bnt.SigningMethod) (string, *UserClaims, error) {
	now := time.Now().UTC()
	ttl := uint32(600) // 10分钟
	expiresAt := now.Add(time.Duration(ttl) * time.Second)

	// 创建用户信息
	userInfo := &UserInfo{}
	userInfo.User.Domain.ID = "5dbc59fd33e94b70a60d9b55633f53d2"
	userInfo.User.Domain.Name = "sys_svc_snms"
	userInfo.User.ID = "5dbc59fd33e94b70a60d9b55633f53d2"
	userInfo.User.Name.Account = "sys_svc_snms"

	// 创建 Claims
	claims := &UserClaims{
		UserInfo: userInfo,
		RegisteredClaims: bnt.RegisteredClaims{
			Issuer:        "test_issuer",
			Subject:       "test_subject",
			Audience:      []string{"sys_svc_snms", "admin"},
			ExpiresAt:     &expiresAt,
			NotBefore:     &now,
			IssuedAt:      &now,
			ID:            fmt.Sprintf("jti/%x", generateID()),
			Ttl:           ttl,
			MaxIssueCount: 123,
			IssueCount:    0,
		},
	}

	// 创建 Token
	token := bnt.NewToken(claims, method)

	// 生成 Token 字符串
	tokenStr, err := token.SignedString()
	if err != nil {
		return "", nil, fmt.Errorf("生成Token失败: %w", err)
	}

	return tokenStr, claims, nil
}

// ==================== 3. 解析 Token ====================

// ParseToken 解析 Token
func ParseToken(tokenStr string, method bnt.SigningMethod) (*UserClaims, *bnt.Token, error) {
	claims := &UserClaims{}
	token, err := bnt.Parse(tokenStr, claims, method)
	if err != nil {
		return nil, nil, fmt.Errorf("解析Token失败: %w", err)
	}

	// 验证 Token
	if err := token.Claims.Valid(); err != nil {
		return nil, nil, fmt.Errorf("Token验证失败: %w", err)
	}

	return claims, token, nil
}

// ==================== 4. 续签 Token ====================

// RefreshToken 续签 Token
func RefreshToken(token *bnt.Token) (string, *UserClaims, error) {
	// 执行续签
	if err := token.Refresh(); err != nil {
		return "", nil, fmt.Errorf("续签失败: %w", err)
	}

	// 获取更新后的 Claims
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return "", nil, errors.New("claims type assertion failed")
	}

	// 验证续签后的 Token
	if err := token.Claims.Valid(); err != nil {
		return "", nil, fmt.Errorf("续签后验证失败: %w", err)
	}

	// 生成新的 Token 字符串
	newTokenStr, err := token.SignedString()
	if err != nil {
		return "", nil, fmt.Errorf("生成新Token失败: %w", err)
	}

	return newTokenStr, claims, nil
}

// ==================== 辅助函数 ====================

func generateID() []byte {
	b := make([]byte, 16)
	rand.Read(b)
	return b
}

// PrintClaims 打印 Claims 信息
func PrintClaims(title string, claims *UserClaims) {
	fmt.Printf("\n📋 %s:\n", title)
	fmt.Printf("   Issuer: %s\n", claims.Issuer)
	fmt.Printf("   Subject: %s\n", claims.Subject)
	fmt.Printf("   ID: %s\n", claims.ID)
	fmt.Printf("   IssuedAt: %v\n", claims.IssuedAt)
	fmt.Printf("   ExpiresAt: %v\n", claims.ExpiresAt)
	fmt.Printf("   NotBefore: %v\n", claims.NotBefore)
	fmt.Printf("   TTL: %d秒\n", claims.Ttl)
	fmt.Printf("   IssueCount: %d\n", claims.IssueCount)
	fmt.Printf("   MaxIssueCount: %d\n", claims.MaxIssueCount)
	fmt.Printf("   Audience: %v\n", claims.Audience)
}

// ==================== Main ====================

func main() {
	fmt.Println("========== 1. 初始化 ==========")
	method, err := Init()
	if err != nil {
		fmt.Printf("初始化失败: %v\n", err)
		return
	}
	fmt.Println("✅ 初始化成功")

	fmt.Println("\n========== 2. 生成 Token ==========")
	tokenStr, claims, err := GenerateToken(method)
	if err != nil {
		fmt.Printf("生成Token失败: %v\n", err)
		return
	}
	fmt.Printf("✅ Token生成成功 (长度: %d)\n", len(tokenStr))
	fmt.Printf("   Token: %s...\n", tokenStr[:30])
	PrintClaims("生成结果", claims)

	fmt.Println("\n========== 3. 解析 Token ==========")
	parsedClaims, parsedToken, err := ParseToken(tokenStr, method)
	if err != nil {
		fmt.Printf("解析Token失败: %v\n", err)
		return
	}
	fmt.Println("✅ Token解析成功")
	PrintClaims("解析结果", parsedClaims)

	fmt.Println("\n========== 4. 续签 Token ==========")
	fmt.Println("等待 10 秒后执行续签...")
	time.Sleep(10 * time.Second)

	newTokenStr, newClaims, err := RefreshToken(parsedToken)
	if err != nil {
		fmt.Printf("续签失败: %v\n", err)
		return
	}
	fmt.Println("✅ Token续签成功")
	fmt.Printf("   新Token长度: %d\n", len(newTokenStr))
	fmt.Printf("   新Token: %s...\n", newTokenStr[:30])
	PrintClaims("续签结果", newClaims)

	// ========== 再次解析验证 ==========
	fmt.Println("\n========== 验证新 Token ==========")
	verifyClaims, _, err := ParseToken(newTokenStr, method)
	if err != nil {
		fmt.Printf("验证新Token失败: %v\n", err)
		return
	}
	fmt.Println("✅ 新Token验证通过")
	PrintClaims("验证结果", verifyClaims)

	// ========== 对比 ==========
	fmt.Println("\n========== 续签前后对比 ==========")
	fmt.Println("  字段      | 续签前                  | 续签后")
	fmt.Println("  ---------|-------------------------|-------------------------")
	fmt.Printf("  IAT      | %s | %s\n", claims.IssuedAt.Format("15:04:05.000"), newClaims.IssuedAt.Format("15:04:05.000"))
	fmt.Printf("  NBF      | %s | %s\n", claims.NotBefore.Format("15:04:05.000"), newClaims.NotBefore.Format("15:04:05.000"))
	fmt.Printf("  EXP      | %s | %s\n", claims.ExpiresAt.Format("15:04:05.000"), newClaims.ExpiresAt.Format("15:04:05.000"))
	fmt.Printf("  ISC      | %d                       | %d\n", claims.IssueCount, newClaims.IssueCount)
	fmt.Printf("  TTL      | %d                       | %d\n", claims.Ttl, newClaims.Ttl)

	// 打印完整 JSON
	fmt.Println("\n========== 完整 JSON ==========")
	beforeJSON, _ := json.Marshal(claims)
	afterJSON, _ := json.Marshal(newClaims)
	fmt.Println("\n续签前:")
	fmt.Println(string(beforeJSON))
	fmt.Println("\n续签后:")
	fmt.Println(string(afterJSON))
}
