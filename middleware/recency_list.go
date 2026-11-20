package middleware

// recencyList holds entries by key, ordered from most to least recently seen,
// so expired entries can be removed from the oldest end without visiting the
// others.
type recencyList[V any] struct {
	entries map[string]*recencyEntry[V]
	newest  *recencyEntry[V]
	oldest  *recencyEntry[V]
}

type recencyEntry[V any] struct {
	key      string
	lastSeen int64
	value    V
	newer    *recencyEntry[V]
	older    *recencyEntry[V]
}

func newRecencyList[V any]() *recencyList[V] {
	return &recencyList[V]{entries: make(map[string]*recencyEntry[V])}
}

func (l *recencyList[V]) len() int {
	return len(l.entries)
}

func (l *recencyList[V]) get(key string) *recencyEntry[V] {
	return l.entries[key]
}

// insert adds key as the most recently seen entry. The key must not exist.
func (l *recencyList[V]) insert(key string, now int64) *recencyEntry[V] {
	entry := &recencyEntry[V]{key: key, lastSeen: now}
	l.entries[key] = entry
	l.pushNewest(entry)
	return entry
}

// touch marks entry as seen at now and moves it to the newest end.
func (l *recencyList[V]) touch(entry *recencyEntry[V], now int64) {
	entry.lastSeen = now
	if l.newest == entry {
		return
	}
	l.unlink(entry)
	l.pushNewest(entry)
}

// expire removes up to limit entries last seen at or before cutoff, oldest
// first, calls removed for each when it is not nil, and returns how many it
// removed.
func (l *recencyList[V]) expire(cutoff int64, limit int, removed func(*recencyEntry[V])) int {
	count := 0
	for count < limit && l.oldest != nil && l.oldest.lastSeen <= cutoff {
		entry := l.oldest
		l.unlink(entry)
		delete(l.entries, entry.key)
		if removed != nil {
			removed(entry)
		}
		count++
	}
	return count
}

func (l *recencyList[V]) pushNewest(entry *recencyEntry[V]) {
	entry.newer = nil
	entry.older = l.newest
	if l.newest != nil {
		l.newest.newer = entry
	}
	l.newest = entry
	if l.oldest == nil {
		l.oldest = entry
	}
}

func (l *recencyList[V]) unlink(entry *recencyEntry[V]) {
	if entry.newer != nil {
		entry.newer.older = entry.older
	} else {
		l.newest = entry.older
	}
	if entry.older != nil {
		entry.older.newer = entry.newer
	} else {
		l.oldest = entry.newer
	}
	entry.newer = nil
	entry.older = nil
}
