package dnsserver

// 查询统计：最近查询流水 + 每个上游的成功/失败与耗时，都是给界面看的。

import (
	"sync"
	"time"
)

type queryLog struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Upstream string    `json:"upstream"`
	Source   string    `json:"source"` // cache | hosts | upstream | error
	Status   string    `json:"status"`
	Answer   string    `json:"answer"`
	CostMS   int64     `json:"cost_ms"`
}

type upstreamStat struct {
	Name     string    `json:"name"`
	Queries  int64     `json:"queries"`
	Errors   int64     `json:"errors"`
	LastMS   int64     `json:"last_ms"`
	AvgMS    int64     `json:"avg_ms"`
	LastErr  string    `json:"last_error"`
	LastUsed time.Time `json:"last_used"`

	totalMS int64
}

type stats struct {
	mu        sync.Mutex
	queries   int64
	cacheHits int64
	hostsHits int64
	failures  int64
	recent    []queryLog
	upstreams map[string]*upstreamStat
}

func newStats() *stats {
	return &stats{upstreams: make(map[string]*upstreamStat)}
}

func (s *stats) record(entry queryLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	switch entry.Source {
	case "cache":
		s.cacheHits++
	case "hosts":
		s.hostsHits++
	case "error":
		s.failures++
	}
	s.recent = append(s.recent, entry)
	if len(s.recent) > recentLimit {
		s.recent = s.recent[len(s.recent)-recentLimit:]
	}
}

func (s *stats) recordUpstream(name string, cost time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.upstreams[name]
	if !ok {
		st = &upstreamStat{Name: name}
		s.upstreams[name] = st
	}
	st.Queries++
	st.LastUsed = time.Now()
	st.LastMS = cost.Milliseconds()
	st.totalMS += st.LastMS
	st.AvgMS = st.totalMS / st.Queries
	if err != nil {
		st.Errors++
		st.LastErr = err.Error()
	} else {
		st.LastErr = ""
	}
}

func (s *stats) snapshot() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	ups := make([]upstreamStat, 0, len(s.upstreams))
	for _, st := range s.upstreams {
		ups = append(ups, *st)
	}
	sortUpstreamStats(ups)

	recent := make([]queryLog, len(s.recent))
	copy(recent, s.recent)
	// 新的在上面，界面不用自己倒
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}

	return map[string]interface{}{
		"queries":    s.queries,
		"cache_hits": s.cacheHits,
		"hosts_hits": s.hostsHits,
		"failures":   s.failures,
		"upstreams":  ups,
		"recent":     recent,
	}
}

// keepOnly 丢掉已经不在配置里的上游统计，否则改名或删除后旧条目会一直挂在界面上
func (s *stats) keepOnly(names map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.upstreams {
		if !names[name] {
			delete(s.upstreams, name)
		}
	}
}

func (s *stats) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries, s.cacheHits, s.hostsHits, s.failures = 0, 0, 0, 0
	s.recent = nil
	s.upstreams = make(map[string]*upstreamStat)
}

// sortUpstreamStats 按查询量从多到少排；条目最多十来个，插入排序足够
func sortUpstreamStats(list []upstreamStat) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].Queries > list[j-1].Queries; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}
