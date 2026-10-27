package main

import "testing"

func TestRunStub(t *testing.T) {
	if got := run([]string{"run"}); got != 1 {
		t.Fatalf("run exit = %d, want 1", got)
	}
	if got := run([]string{"list-providers"}); got != 2 {
		t.Fatalf("unknown exit = %d, want 2", got)
	}
	if got := run(nil); got != 1 {
		t.Fatalf("default exit = %d, want 1", got)
	}
}
