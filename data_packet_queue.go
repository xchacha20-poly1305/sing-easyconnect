package easyconnect

import (
	"context"
	"sync"
)

type dataPacketQueue[T any] struct {
	access   sync.Mutex
	items    []T
	head     int
	length   int
	notEmpty queueSignal
	notFull  queueSignal
	closed   bool
}

func newDataPacketQueue[T any](capacity int) *dataPacketQueue[T] {
	return &dataPacketQueue[T]{items: make([]T, capacity)}
}

func (q *dataPacketQueue[T]) TryPushBatch(items []T) int {
	q.access.Lock()
	defer q.access.Unlock()
	pushed := 0
	for pushed < len(items) && !q.closed && q.length < len(q.items) {
		q.pushLocked(items[pushed])
		pushed++
	}
	return pushed
}

func (q *dataPacketQueue[T]) Push(ctx context.Context, item T) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		q.access.Lock()
		if q.closed {
			q.access.Unlock()
			return false
		}
		if q.length < len(q.items) {
			q.pushLocked(item)
			q.access.Unlock()
			return true
		}
		notFull := q.notFull.waitLocked()
		q.access.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-notFull:
		}
	}
}

func (q *dataPacketQueue[T]) pushLocked(item T) {
	wasEmpty := q.length == 0
	tail := (q.head + q.length) % len(q.items)
	q.items[tail] = item
	q.length++
	if wasEmpty {
		q.notEmpty.signalLocked()
	}
}

func (q *dataPacketQueue[T]) Pop(maximumItems int) []T {
	return q.PopInto(nil, maximumItems)
}

func (q *dataPacketQueue[T]) PopInto(items []T, maximumItems int) []T {
	q.access.Lock()
	count := q.length
	if maximumItems > 0 {
		count = min(count, maximumItems)
	}
	if count == 0 {
		q.access.Unlock()
		return items[:0]
	}
	if cap(items) < count {
		items = make([]T, 0, count)
	}
	items = items[:0]
	for index := range count {
		itemIndex := (q.head + index) % len(q.items)
		items = append(items, q.items[itemIndex])
		var zero T
		q.items[itemIndex] = zero
	}
	q.head = (q.head + count) % len(q.items)
	q.length -= count
	q.notFull.signalLocked()
	q.access.Unlock()
	return items
}

func (q *dataPacketQueue[T]) Wake() <-chan struct{} {
	q.access.Lock()
	defer q.access.Unlock()
	if q.length > 0 || q.closed {
		return alreadySignalled
	}
	return q.notEmpty.waitLocked()
}

func (q *dataPacketQueue[T]) Closed() bool {
	q.access.Lock()
	defer q.access.Unlock()
	return q.closed
}

func (q *dataPacketQueue[T]) Close() {
	q.access.Lock()
	if !q.closed {
		q.closed = true
		q.notEmpty.signalLocked()
		q.notFull.signalLocked()
	}
	q.access.Unlock()
}

func (q *dataPacketQueue[T]) Drain(release func(T)) {
	for _, item := range q.Pop(0) {
		if release != nil {
			release(item)
		}
	}
}

var alreadySignalled = func() chan struct{} {
	ready := make(chan struct{})
	close(ready)
	return ready
}()

type queueSignal struct {
	waiting chan struct{}
}

func (s *queueSignal) waitLocked() <-chan struct{} {
	if s.waiting == nil {
		s.waiting = make(chan struct{})
	}
	return s.waiting
}

func (s *queueSignal) signalLocked() {
	if s.waiting == nil {
		return
	}
	close(s.waiting)
	s.waiting = nil
}
