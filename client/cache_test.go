package client

import (
	"testing"
	"time"
)

func TestCache_SetGet(t *testing.T) {
	c := newCache(time.Hour)
	c.set("k", []byte("v"))

	got, ok := c.get("k")
	if !ok || string(got) != "v" {
		t.Fatalf("expected hit 'v', got %q ok=%v", got, ok)
	}
}

func TestCache_Miss(t *testing.T) {
	c := newCache(time.Hour)
	if _, ok := c.get("absent"); ok {
		t.Fatal("expected miss")
	}
}

func TestCache_Expiry(t *testing.T) {
	c := newCache(time.Nanosecond)
	c.set("k", []byte("v"))
	time.Sleep(time.Millisecond)

	if _, ok := c.get("k"); ok {
		t.Fatal("expected expired entry to miss")
	}
}

func TestCache_Disabled(t *testing.T) {
	c := newCache(0)
	c.set("k", []byte("v"))

	if _, ok := c.get("k"); ok {
		t.Fatal("expected disabled cache to never hit")
	}
}
