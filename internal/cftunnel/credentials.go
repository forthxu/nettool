package cftunnel

// 从 cloudflared 凭证文件算出连接器令牌。
//
// 这两样东西装的是同一份秘密，只是形状不同：
//
//	凭证文件 ~/.cloudflared/<UUID>.json   {"AccountTag":…,"TunnelID":…,"TunnelSecret":…}
//	连接器令牌（TUNNEL_TOKEN）            base64({"a":AccountTag,"t":TunnelID,"s":TunnelSecret})
//
// 认出这一点，导入本机已有的隧道就**不需要 Cloudflare API Token**，也不用联网：
// 凭证文件已经在那儿了，令牌当场算得出来。（要 Token 的是把规则搬到云端那一步，
// 见 Manager.Import。）

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// credentials 是 cloudflared 凭证文件的形状。字段名是大写开头的那套，
// 不是令牌里的 a/t/s。
type credentials struct {
	AccountTag   string `json:"AccountTag"`
	TunnelID     string `json:"TunnelID"`
	TunnelSecret string `json:"TunnelSecret"`
	// Endpoint 只在 FedRAMP 那套环境里非空。它不进令牌，所以这种凭证转不成令牌，
	// 与其算出一个跑不起来的令牌，不如当场说清楚。
	Endpoint string `json:"Endpoint,omitempty"`
}

// tokenPayload 是令牌 base64 解出来的内容
type tokenPayload struct {
	AccountTag   string `json:"a"`
	TunnelID     string `json:"t"`
	TunnelSecret string `json:"s"`
}

func (c credentials) validate() error {
	switch {
	case c.AccountTag == "":
		return fmt.Errorf("凭证里没有 AccountTag")
	case c.TunnelID == "":
		return fmt.Errorf("凭证里没有 TunnelID")
	case c.TunnelSecret == "":
		return fmt.Errorf("凭证里没有 TunnelSecret")
	case c.Endpoint != "":
		return fmt.Errorf("这份凭证带着 Endpoint=%q（FedRAMP 环境），本工具暂不支持", c.Endpoint)
	}
	return nil
}

// tokenFromCredentials 把凭证文件的内容算成连接器令牌
func tokenFromCredentials(c credentials) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(tokenPayload{
		AccountTag: c.AccountTag, TunnelID: c.TunnelID, TunnelSecret: c.TunnelSecret,
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// readCredentialsFile 读一份 cloudflared 凭证文件
func readCredentialsFile(path string) (credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return credentials{}, fmt.Errorf("读取凭证文件失败: %v", err)
	}
	var c credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return credentials{}, fmt.Errorf("%s 不是 cloudflared 凭证文件: %v", path, err)
	}
	if err := c.validate(); err != nil {
		return credentials{}, fmt.Errorf("%s: %v", path, err)
	}
	return c, nil
}
