package easyconnect

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDataPacketQueueWraps(t *testing.T) {
	t.Parallel()
	queue := newDataPacketQueue[int](2)
	ctx := t.Context()
	require.Equal(t, 2, queue.PushBatch(ctx, []int{1, 2}))
	require.Equal(t, []int{1}, queue.Pop(1))
	require.Equal(t, 1, queue.PushBatch(ctx, []int{3}))
	require.Equal(t, []int{2, 3}, queue.Pop(0))
}

func TestDataPacketQueueDrain(t *testing.T) {
	t.Parallel()
	queue := newDataPacketQueue[int](4)
	require.Equal(t, 3, queue.PushBatch(t.Context(), []int{1, 2, 3}))
	var drained []int
	queue.Drain(func(item int) {
		drained = append(drained, item)
	})
	require.Equal(t, []int{1, 2, 3}, drained)
	require.Empty(t, queue.Pop(0))
}

func TestDataPacketQueuePushWaitsUntilSpace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		queue := newDataPacketQueue[int](1)
		require.Equal(t, 1, queue.PushBatch(t.Context(), []int{1}))

		done := make(chan int, 1)
		go func() {
			done <- queue.PushBatch(t.Context(), []int{2})
		}()
		synctest.Wait()
		require.Empty(t, done)

		require.Equal(t, []int{1}, queue.Pop(1))
		synctest.Wait()
		require.Equal(t, 1, <-done)
		require.Equal(t, []int{2}, queue.Pop(1))
	})
}

func TestDataPacketQueuePushStopsOnCancel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		queue := newDataPacketQueue[int](1)
		require.Equal(t, 1, queue.PushBatch(t.Context(), []int{1}))

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan int, 1)
		go func() {
			done <- queue.PushBatch(ctx, []int{2})
		}()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.Equal(t, 0, <-done)
		require.Equal(t, []int{1}, queue.Pop(1))
	})
}

func TestDataPacketQueuePushStopsWhenClosed(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		queue := newDataPacketQueue[int](1)
		require.Equal(t, 1, queue.PushBatch(t.Context(), []int{1}))

		done := make(chan int, 1)
		go func() {
			done <- queue.PushBatch(t.Context(), []int{2})
		}()
		synctest.Wait()
		queue.Close()
		synctest.Wait()
		require.Equal(t, 0, <-done)
		require.True(t, queue.Closed())
	})
}

func TestDataPacketQueueWake(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		queue := newDataPacketQueue[int](1)
		select {
		case <-queue.Wake():
			t.Fatal("empty queue must not be ready")
		default:
		}

		go func() {
			queue.PushBatch(t.Context(), []int{7})
		}()
		synctest.Wait()
		select {
		case <-queue.Wake():
		default:
			t.Fatal("queue must wake after a push")
		}
		require.Equal(t, []int{7}, queue.Pop(1))
	})
}
