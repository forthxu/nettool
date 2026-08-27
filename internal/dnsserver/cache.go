package dnsserver

// 应答缓存。存的是入库那一刻的报文，取出来时按已缓存时长把 TTL 扣掉，
// 否则客户端会以为记录比实际新。

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type cacheEntry struct {
	msg       dnsmessage.Message
	storedAt  time.Time
	expiresAt time.Time
}

type cache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	max     int
}

func newCache(max int) *cache {
	if max <= 0 {
		max = 1024
	}
	return &cache{entries: make(map[string]*cacheEntry), max: max}
}

func cacheKey(q dnsmessage.Question) string {
	return strings.ToLower(q.Name.String()) + "|" + strconv.Itoa(int(q.Type)) + "|" + strconv.Itoa(int(q.Class))
}

// get 返回一份改好 TTL 的副本
func (c *cache) get(key string, now time.Time) (dnsmessage.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return dnsmessage.Message{}, false
	}
	if !now.Before(e.expiresAt) {
		delete(c.entries, key)
		return dnsmessage.Message{}, false
	}

	elapsed := uint32(now.Sub(e.storedAt) / time.Second)
	msg := e.msg
	msg.Answers = decayTTL(e.msg.Answers, elapsed)
	msg.Authorities = decayTTL(e.msg.Authorities, elapsed)
	msg.Additionals = decayTTL(e.msg.Additionals, elapsed)
	return msg, true
}

func (c *cache) put(key string, msg dnsmessage.Message, ttl time.Duration, now time.Time) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[key] = &cacheEntry{msg: msg, storedAt: now, expiresAt: now.Add(ttl)}
}

// evictLocked 先清过期项，还是满就随手丢掉一批。
// 这是台局域网小工具，没必要为严格 LRU 维护一条链表。
func (c *cache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	drop := len(c.entries)/8 + 1
	for k := range c.entries {
		delete(c.entries, k)
		if drop--; drop <= 0 {
			return
		}
	}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *cache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

// decayTTL 复制一份记录并按已缓存时长扣减 TTL；OPT 的 TTL 字段是扩展标志位，不能动
func decayTTL(rrs []dnsmessage.Resource, elapsed uint32) []dnsmessage.Resource {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dnsmessage.Resource, len(rrs))
	copy(out, rrs)
	for i := range out {
		if out[i].Header.Type == dnsmessage.TypeOPT {
			continue
		}
		if out[i].Header.TTL > elapsed {
			out[i].Header.TTL -= elapsed
		} else {
			out[i].Header.TTL = 1
		}
	}
	return out
}
