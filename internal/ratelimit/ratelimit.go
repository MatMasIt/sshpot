// Package ratelimit implements a lossy counter bloom filter
// basically, ip % N buckets.
// Each bucket contains the next time it can be used again.
// This has a probability of collision, that in our case is acceptable, since it would only cause some IPs to be rate limited more than they should, but never less.
package ratelimit

import (
	"hash/fnv"
	"net"
	"sync"
	"time"
)

// Config holds rate-limiter tuning parameters.
type Config struct {
	BucketCount  uint32        // number of buckets in the bloom filter
	RestInterval time.Duration // interval after which a bucket becomes available again if not hit
}

// bucket is a single leaky-bucket counter.
type bucket struct {
	mu      sync.Mutex
	nextUse time.Time // when the bucket can be used again
}

func newBucket() *bucket {
	use := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC) // start at 0
	return &bucket{nextUse: use}
}

// Gate is the two-layer rate limiter.
type Gate struct {
	buckets []*bucket

	restInterval time.Duration
}

// New constructs a Gate and starts a background pruning goroutine.
func New(cfg Config) *Gate {
	g := &Gate{
		buckets:      make([]*bucket, cfg.BucketCount),
		restInterval: cfg.RestInterval,
	}
	// Initialize buckets
	for i := range g.buckets {
		g.buckets[i] = newBucket()
	}
	return g
}

// Allow returns true if the connection from addr should proceed.
// Both the global and per-IP bucket must have a token available.
func (g *Gate) Allow(addr net.Addr) bool {

	ipStr, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		ip := net.ParseIP(ipStr)

		// localhost bypass
		if ip != nil && ip.IsLoopback() {
			return true
		}
	} else {
		// If we can't parse the address, be permissive and allow it. It should not be possible to get here, but better to allow than to block all traffic.
		return true
	}

	index := stringToBucketIndex(ipStr, uint32(len(g.buckets)))
	b := g.buckets[index]
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	if now.Before(b.nextUse) {
		return false
	}

	b.nextUse = now.Add(g.restInterval)
	return true
}

func stringToBucketIndex(addr string, buckets uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(addr))

	return h.Sum32() % buckets
}
