//go:build linux

package shield

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RunVictim plays the attacker for the simulation. It renames itself to
// VictimComm and tries operations the demo rules forbid, printing one line
// per attempt: "<action>\t<outcome>". All operations are harmless: the files
// are canaries, the shell runs `true`, the ptrace target is a sleeping child.
func RunVictim(w io.Writer) error {
	// comm is per thread, so stay on the thread that was renamed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := append([]byte(VictimComm), 0)
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0); err != nil {
		return err
	}

	report := func(action string, err error) {
		fmt.Fprintf(w, "%s\t%s\n", action, outcome(err))
		if f, ok := w.(*os.File); ok {
			f.Sync()
		}
	}

	report("execve /bin/sh", exec.Command("/bin/sh", "-c", "true").Run())

	f, err := os.Open(CanaryDir + "/block-me")
	if err == nil {
		f.Close()
	}
	report("open "+CanaryDir+"/block-me", err)

	sleeper := exec.Command("sleep", "5")
	if err := sleeper.Start(); err == nil {
		perr := unix.PtraceAttach(sleeper.Process.Pid)
		if perr == nil {
			unix.PtraceDetach(sleeper.Process.Pid)
		}
		report("ptrace attach", perr)
		sleeper.Process.Kill()
		sleeper.Wait()
	}

	// Last: if the KILL rule works this process dies on the open below and
	// never prints, which the parent reports as KILLED.
	fmt.Fprintf(w, "open %s/kill-me\tPENDING\n", CanaryDir)
	if f, ok := w.(*os.File); ok {
		f.Sync()
	}
	if f, err := os.Open(CanaryDir + "/kill-me"); err == nil {
		f.Close()
		report("open "+CanaryDir+"/kill-me", nil)
	} else {
		report("open "+CanaryDir+"/kill-me", err)
	}
	return nil
}

func outcome(err error) string {
	switch {
	case err == nil:
		return "ALLOWED"
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "operation not permitted"):
		return "BLOCKED (EPERM)"
	default:
		return "ERROR: " + err.Error()
	}
}

// parseAttempts reads RunVictim output. A trailing PENDING line means the
// process never reported back, i.e. it was killed.
func parseAttempts(out []byte) []Attempt {
	var res []Attempt
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		action, outcome, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		if outcome == "PENDING" {
			res = append(res, Attempt{Action: action, Outcome: "KILLED (SIGKILL)"})
			continue
		}
		// a real result replaces the pending line of the same action
		if n := len(res); n > 0 && res[n-1].Action == action {
			res = res[:n-1]
		}
		res = append(res, Attempt{Action: action, Outcome: outcome})
	}
	return res
}
