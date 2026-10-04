package dnsproxy

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	key     string
	msg     *dns.Msg
	expires time.Time
	// storedTTL 为写入时的 TTL，用于回放时递减。
	stored time.Time
}

// cache 是一个带 TTL 的 LRU 缓存。
type cache struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
	now   func() time.Time // 便于测试
}

func newCache(capacity int) *cache {
	return &cache{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[string]*list.Element, capacity),
	}
}

func (c *cache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *cache) get(key string) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	now := c.clock()
	if now.After(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.ll.MoveToFront(el)

	// 按已经过去的时间递减 TTL，避免把过期时间越拖越长。
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	m := e.msg.Copy()
	for _, rrs := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 1
			}
		}
	}
	return m, true
}

func (c *cache) put(key string, m *dns.Msg, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	e := &entry{key: key, msg: m.Copy(), expires: now.Add(ttl), stored: now}
	if el, ok := c.items[key]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(e)
	for c.ll.Len() > c.cap {
		last := c.ll.Back()
		if last == nil {
			break
		}
		c.ll.Remove(last)
		delete(c.items, last.Value.(*entry).key)
	}
}

// Len 返回当前条目数（含尚未清理的过期项）。
func (c *cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Flush 清空缓存。切换节点时调用，避免沿用上一个出口的解析结果。
func (r *Resolver) Flush() {
	r.init()
	if r.cache == nil {
		return
	}
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	r.cache.ll.Init()
	r.cache.items = make(map[string]*list.Element, r.cache.cap)
}
