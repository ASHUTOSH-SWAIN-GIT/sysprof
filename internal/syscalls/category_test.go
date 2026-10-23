package syscalls

import "testing"

func TestCategory(t *testing.T) {
	cases := map[string]string{
		"read":              CategoryFile,
		"openat2":           CategoryFile,
		"inotify_add_watch": CategoryFile,
		"mmap":              CategoryMemory,
		"sendmsg":           CategoryNetwork,
		"clone3":            CategoryProcess,
		"futex_wait":        CategorySync,
		"io_uring_enter":    CategorySync,
		"rt_sigaction":      CategorySignal,
		"clock_nanosleep":   CategoryTime,
		"not_a_syscall":     CategoryOther,
	}
	for name, want := range cases {
		if got := Category(name); got != want {
			t.Errorf("Category(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCategoryTableIsConsistent(t *testing.T) {
	known := map[string]bool{}
	for _, c := range Categories {
		known[c] = true
	}
	for name, c := range categoryOf {
		if !known[c] {
			t.Errorf("%q mapped to unknown category %q", name, c)
		}
	}
}
