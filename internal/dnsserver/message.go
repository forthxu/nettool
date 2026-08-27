package dnsserver

// DNS 报文层面的小工具：改事务 ID、拼应答、把记录整理成人能读的一行。

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func setMsgID(msg []byte, id uint16) {
	if len(msg) >= 2 {
		msg[0] = byte(id >> 8)
		msg[1] = byte(id)
	}
}

func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// buildResponse 拼一个只有问题段（可能再加几条答案）的应答
func buildResponse(reqHdr dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 reqHdr.ID,
			Response:           true,
			OpCode:             reqHdr.OpCode,
			RecursionDesired:   reqHdr.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Answers: answers,
	}
	if q.Name.Length > 0 {
		msg.Questions = []dnsmessage.Question{q}
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil
	}
	return packed
}

// truncatedResponse 告诉客户端"应答太大，请改用 TCP 再问一次"
func truncatedResponse(reqHdr dnsmessage.Header, q dnsmessage.Question) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 reqHdr.ID,
			Response:           true,
			OpCode:             reqHdr.OpCode,
			Truncated:          true,
			RecursionDesired:   reqHdr.RecursionDesired,
			RecursionAvailable: true,
		},
	}
	if q.Name.Length > 0 {
		msg.Questions = []dnsmessage.Question{q}
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil
	}
	return packed
}

func ipResource(q dnsmessage.Question, ip net.IP) (dnsmessage.Resource, bool) {
	hdr := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
	if v4 := ip.To4(); v4 != nil {
		var a dnsmessage.AResource
		copy(a.A[:], v4)
		return dnsmessage.Resource{Header: hdr, Body: &a}, true
	}
	if v6 := ip.To16(); v6 != nil {
		var aaaa dnsmessage.AAAAResource
		copy(aaaa.AAAA[:], v6)
		return dnsmessage.Resource{Header: hdr, Body: &aaaa}, true
	}
	return dnsmessage.Resource{}, false
}

// udpBufferSize 读出请求里 EDNS0 声明的接收缓冲区大小，没声明就是传统的 512
func udpBufferSize(req []byte) int {
	const classic = 512
	var p dnsmessage.Parser
	if _, err := p.Start(req); err != nil {
		return classic
	}
	if err := p.SkipAllQuestions(); err != nil {
		return classic
	}
	if err := p.SkipAllAnswers(); err != nil {
		return classic
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return classic
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return classic
		}
		if h.Type == dnsmessage.TypeOPT {
			// OPT 记录借 Class 字段放接收缓冲区大小
			size := int(h.Class)
			if size < classic {
				size = classic
			}
			if size > udpBufSize {
				size = udpBufSize
			}
			return size
		}
		if err := p.SkipAdditional(); err != nil {
			return classic
		}
	}
}

// rcodeName 用 DNS 圈子里通行的写法，dnsmessage 自带的 String() 会返回 "RCodeSuccess"
func rcodeName(c dnsmessage.RCode) string {
	switch c {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return strings.TrimPrefix(c.String(), "RCode")
	}
}

// typeName 把 dnsmessage 的 "TypeA" 变成界面上好看的 "A"
func typeName(t dnsmessage.Type) string {
	s := t.String()
	if strings.HasPrefix(s, "Type") {
		return s[len("Type"):]
	}
	return s
}

// queryTypes 是界面上「测试解析」允许选的记录类型
var queryTypes = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"AAAA":  dnsmessage.TypeAAAA,
	"CNAME": dnsmessage.TypeCNAME,
	"MX":    dnsmessage.TypeMX,
	"NS":    dnsmessage.TypeNS,
	"PTR":   dnsmessage.TypePTR,
	"SOA":   dnsmessage.TypeSOA,
	"SRV":   dnsmessage.TypeSRV,
	"TXT":   dnsmessage.TypeTXT,
}

func summarizeAnswers(answers []dnsmessage.Resource) string {
	if len(answers) == 0 {
		return "（无记录）"
	}
	parts := make([]string, 0, len(answers))
	for _, rr := range answers {
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			parts = append(parts, net.IP(b.A[:]).String())
		case *dnsmessage.AAAAResource:
			parts = append(parts, net.IP(b.AAAA[:]).String())
		case *dnsmessage.CNAMEResource:
			parts = append(parts, "CNAME "+b.CNAME.String())
		case *dnsmessage.MXResource:
			parts = append(parts, "MX "+b.MX.String())
		case *dnsmessage.NSResource:
			parts = append(parts, "NS "+b.NS.String())
		case *dnsmessage.PTRResource:
			parts = append(parts, "PTR "+b.PTR.String())
		case *dnsmessage.TXTResource:
			parts = append(parts, "TXT "+strings.Join(b.TXT, " "))
		case *dnsmessage.SRVResource:
			parts = append(parts, fmt.Sprintf("SRV %s:%d", b.Target.String(), b.Port))
		default:
			parts = append(parts, typeName(rr.Header.Type))
		}
		if len(parts) >= 6 {
			parts = append(parts, "…")
			break
		}
	}
	return strings.Join(parts, ", ")
}
