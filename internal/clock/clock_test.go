package clock

import "testing"

func TestFreezeAndAdvance(t *testing.T) {
	c := New()
	c.realNow = func() int64 { return 100 }
	c.Freeze()
	c.Advance(20)
	if got := c.Now(); got != 120 {
		t.Fatalf("Now() = %d, want 120", got)
	}
	c.Unfreeze()
	if got := c.Now(); got != 120 {
		t.Fatalf("unfrozen Now() = %d, want 120", got)
	}
}

func TestClockModes(t *testing.T) {
	c := New()
	c.realNow = func() int64 { return 100 }
	c.SetOffset(10)
	if offset, frozen, now := c.State(); offset != 10 || frozen || now != 110 {
		t.Fatalf("state = %d %v %d", offset, frozen, now)
	}
	c.Advance(-5)
	if got := c.Now(); got != 105 {
		t.Fatalf("Now() = %d", got)
	}
	c.Freeze()
	c.Freeze()
	if offset, frozen, now := c.State(); offset != 5 || !frozen || now != 105 {
		t.Fatalf("frozen state = %d %v %d", offset, frozen, now)
	}
	c.Unfreeze()
	c.Unfreeze()
}
