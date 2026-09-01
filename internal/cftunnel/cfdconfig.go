package cftunnel

// 读 cloudflared 自己的配置文件（config.yml）。**只读，从不写。**
//
// 这是为了接住「已经在用 cloudflared 的人」：他们手上有 `cloudflared tunnel
// create` 建的隧道、一份凭证文件和一份自己写的 config.yml。导入时把里面的
// ingress 规则读出来搬到云端（见 Manager.Import），文件本身一个字节都不动——
// 那份文件通常有注释、有注释掉的备用规则，还被开机脚本引用着，重写它得不偿失。
//
// 用 gopkg.in/yaml.v3 而不是自己按行解析：这些文件是别人手写的，缩进、引号、
// 折行、锚点各种写法都可能出现，认错一条规则比读不出来更糟。

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// cfdConfig 是 config.yml 里本工具关心的那几项。
//
// cloudflared 的配置项有几十个（loglevel、metrics、protocol……），这里只列出要读
// 的三项，其余的 yaml 解析时自然忽略——反正不会写回去。
type cfdConfig struct {
	Tunnel          string        `yaml:"tunnel"`
	CredentialsFile string        `yaml:"credentials-file"`
	Ingress         []IngressRule `yaml:"ingress"`
}

// parseCFDConfig 解析一份 cloudflared 配置文件
func parseCFDConfig(data []byte) (cfdConfig, error) {
	var cfg cfdConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfdConfig{}, fmt.Errorf("解析配置失败: %v", err)
	}
	return cfg, nil
}

// readCFDConfig 读并解析一份 config.yml
func readCFDConfig(path string) (cfdConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cfdConfig{}, fmt.Errorf("读取配置文件失败: %v", err)
	}
	cfg, err := parseCFDConfig(data)
	if err != nil {
		return cfdConfig{}, fmt.Errorf("%s: %v", path, err)
	}
	return cfg, nil
}
