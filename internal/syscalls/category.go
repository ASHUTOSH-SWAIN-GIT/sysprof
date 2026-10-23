package syscalls

import "strings"

// Categories group syscalls by the resource they mostly touch, so a workload
// can be described as file heavy, network heavy and so on.
const (
	CategoryFile    = "file"
	CategoryMemory  = "memory"
	CategoryNetwork = "network"
	CategoryProcess = "process"
	CategorySync    = "sync"
	CategorySignal  = "signal"
	CategoryTime    = "time"
	CategoryOther   = "other"
)

// Categories is the display order used by the CLI and the web UI.
var Categories = []string{
	CategoryFile, CategoryMemory, CategoryNetwork, CategoryProcess,
	CategorySync, CategorySignal, CategoryTime, CategoryOther,
}

var categoryOf = map[string]string{}

func add(category string, names ...string) {
	for _, name := range names {
		categoryOf[name] = category
	}
}

func init() {
	add(CategoryFile,
		"read", "write", "open", "openat", "openat2", "close", "close_range",
		"stat", "fstat", "lstat", "newfstatat", "fstatat", "statx", "access",
		"faccessat", "faccessat2", "chdir", "fchdir", "getcwd", "mkdir",
		"mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat",
		"renameat2", "link", "linkat", "symlink", "symlinkat", "readlink",
		"readlinkat", "chmod", "fchmod", "fchmodat", "fchmodat2", "chown",
		"fchown", "lchown", "fchownat", "truncate", "ftruncate", "fallocate",
		"fsync", "fdatasync", "sync", "syncfs", "sync_file_range", "dup",
		"dup2", "dup3", "fcntl", "flock", "getdents", "getdents64", "pread64",
		"pwrite64", "readv", "writev", "preadv", "pwritev", "preadv2",
		"pwritev2", "sendfile", "copy_file_range", "splice", "tee", "vmsplice",
		"lseek", "creat", "mknod", "mknodat", "umask", "utime", "utimes",
		"utimensat", "futimesat", "fadvise64", "readahead", "memfd_create",
		"name_to_handle_at", "open_by_handle_at", "statfs", "fstatfs", "chroot",
		"pivot_root", "mount", "umount2", "mount_setattr", "open_tree",
		"move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "quotactl",
		"quotactl_fd", "acct", "fchroot", "inotify_init", "inotify_init1",
		"inotify_add_watch", "inotify_rm_watch", "fanotify_init", "fanotify_mark",
	)
	add(CategoryMemory,
		"mmap", "munmap", "mremap", "mprotect", "brk", "madvise", "msync",
		"mincore", "mlock", "munlock", "mlock2", "mlockall", "munlockall",
		"mbind", "set_mempolicy", "get_mempolicy", "migrate_pages",
		"move_pages", "remap_file_pages", "membarrier", "mseal", "pkey_mprotect",
		"pkey_alloc", "pkey_free", "userfaultfd", "process_madvise",
		"process_mrelease", "process_vm_readv", "process_vm_writev",
	)
	add(CategoryNetwork,
		"socket", "socketpair", "bind", "listen", "accept", "accept4",
		"connect", "getsockname", "getpeername", "sendto", "recvfrom",
		"sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "setsockopt",
		"getsockopt", "shutdown",
	)
	add(CategoryProcess,
		"clone", "clone3", "fork", "vfork", "execve", "execveat", "exit",
		"exit_group", "wait4", "waitid", "getpid", "getppid", "gettid",
		"getuid", "geteuid", "getgid", "getegid", "setuid", "setgid",
		"setreuid", "setregid", "setresuid", "setresgid", "setfsuid",
		"setfsgid", "getgroups", "setgroups", "setpgid", "getpgid", "getpgrp",
		"setsid", "getsid", "kill", "tkill", "tgkill", "pidfd_open",
		"pidfd_getfd", "pidfd_send_signal", "prctl", "prlimit64", "arch_prctl",
		"personality", "set_tid_address", "set_robust_list", "get_robust_list",
		"unshare", "setns", "sched_yield", "sched_setparam", "sched_getparam",
		"sched_setscheduler", "sched_getscheduler", "sched_setaffinity",
		"sched_getaffinity", "sched_setattr", "sched_getattr",
		"sched_get_priority_max", "sched_get_priority_min",
		"sched_rr_get_interval", "ioprio_set", "ioprio_get", "capget", "capset",
		"seccomp", "setrlimit", "getrlimit", "getrusage", "sysinfo", "uname",
		"getcpu", "rseq", "restart_syscall", "bpf", "perf_event_open", "kcmp",
		"ptrace", "landlock_create_ruleset", "landlock_add_rule",
		"landlock_restrict_self", "lsm_get_self_attr", "lsm_set_self_attr",
		"lsm_list_modules",
	)
	add(CategorySync,
		"futex", "futex_wait", "futex_wake", "futex_waitv", "futex_requeue",
		"futex_time64", "epoll_create", "epoll_create1", "epoll_ctl",
		"epoll_wait", "epoll_pwait", "epoll_pwait2", "poll", "ppoll", "select",
		"pselect6", "eventfd", "eventfd2", "io_setup", "io_destroy",
		"io_getevents", "io_submit", "io_cancel", "io_pgetevents",
		"io_uring_setup", "io_uring_enter", "io_uring_register", "semget",
		"semop", "semctl", "semtimedop", "msgget", "msgsnd", "msgrcv",
		"msgctl", "shmget", "shmat", "shmctl", "shmdt", "mq_open",
		"mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
		"mq_getsetattr",
	)
	add(CategorySignal,
		"rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait",
		"rt_sigsuspend", "rt_sigreturn", "rt_sigqueueinfo",
		"rt_tgsigqueueinfo", "sigaltstack", "signalfd", "signalfd4", "pause",
	)
	add(CategoryTime,
		"clock_gettime", "clock_settime", "clock_getres", "clock_adjtime",
		"clock_nanosleep", "clock_gettime64", "clock_settime64",
		"clock_adjtime64", "clock_getres_time64", "clock_nanosleep_time64",
		"gettimeofday", "settimeofday", "time", "adjtimex", "nanosleep",
		"timer_create", "timer_settime", "timer_gettime", "timer_getoverrun",
		"timer_delete", "timerfd_create", "timerfd_settime", "timerfd_gettime",
		"timer_gettime64", "timer_settime64", "timerfd_gettime64",
		"timerfd_settime64", "getitimer", "setitimer", "alarm", "times",
	)
}

// Category returns the group for a syscall name. Unknown names fall back to
// prefixes, then to "other".
func Category(name string) string {
	if c, ok := categoryOf[name]; ok {
		return c
	}
	switch {
	case strings.HasPrefix(name, "futex"), strings.HasPrefix(name, "epoll"),
		strings.HasPrefix(name, "sem"), strings.HasPrefix(name, "msg"),
		strings.HasPrefix(name, "shm"), strings.HasPrefix(name, "io_uring"):
		return CategorySync
	case strings.HasPrefix(name, "signalfd"), strings.HasPrefix(name, "rt_sig"):
		return CategorySignal
	case strings.HasPrefix(name, "timerfd"), strings.HasPrefix(name, "timer_"),
		strings.HasPrefix(name, "clock_"):
		return CategoryTime
	case strings.HasPrefix(name, "inotify"), strings.HasPrefix(name, "fanotify"):
		return CategoryFile
	case strings.HasPrefix(name, "landlock"):
		return CategoryProcess
	}
	return CategoryOther
}
