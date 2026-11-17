package main

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>

// What the kernel knows about a process: executable path (can't be faked with exec -a, unlike argv or ps's comm),
// parent, start time and working directory. name is the kernel's process name (from the executed file's name, not
// argv): proc_pidpath returns nothing once the executable was deleted, e.g. by a Homebrew upgrade of a running agent.
static int pinfo(int pid, char *exe, int exelen, char *name, int namelen, char *cwd, int cwdlen, int *ppid, long long *start) {
	struct proc_bsdinfo bi;
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != sizeof bi) return -1;
	*ppid = (int)bi.pbi_ppid;
	*start = (long long)bi.pbi_start_tvsec * 1000000LL + (long long)bi.pbi_start_tvusec;
	strlcpy(name, bi.pbi_name[0] ? bi.pbi_name : bi.pbi_comm, namelen);
	exe[0] = 0;
	proc_pidpath(pid, exe, exelen);
	cwd[0] = 0;
	struct proc_vnodepathinfo vi;
	if (proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vi, sizeof vi) == sizeof vi) {
		strlcpy(cwd, vi.pvi_cdir.vip_path, cwdlen);
	}
	return 0;
}
*/
import "C"

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc is one process of a caller chain. Exe, Name, Start and Cwd come from the kernel; Args (for showing) from ps, which
// the process itself controls.
type proc struct {
	PID   int
	Exe   string
	Name  string // the kernel's process name (pbi_name, else pbi_comm): stands in for Exe when the executable was deleted
	Args  string
	Cwd   string
	Start int64 // µs since the epoch; with PID it identifies the process (PIDs get reused)
}

func procInfo(pid int) (p proc, ppid int, ok bool) {
	exe := make([]byte, 4096)
	name := make([]byte, 2*C.MAXCOMLEN+1)
	cwd := make([]byte, 1024)
	var cppid C.int
	var start C.longlong
	if C.pinfo(C.int(pid), (*C.char)(unsafe.Pointer(&exe[0])), 4096, (*C.char)(unsafe.Pointer(&name[0])), C.int(len(name)), (*C.char)(unsafe.Pointer(&cwd[0])), 1024, &cppid, &start) != 0 {
		return proc{}, 0, false
	}
	cstr := func(b []byte) string {
		if i := strings.IndexByte(string(b), 0); i >= 0 {
			return string(b[:i])
		}
		return string(b)
	}
	return proc{PID: pid, Exe: cstr(exe), Name: cstr(name), Cwd: cstr(cwd), Start: int64(start)}, int(cppid), true
}

// procAlive reports whether pid is still the process that started at start.
func procAlive(pid int, start int64) bool {
	p, _, ok := procInfo(pid)
	return ok && start != 0 && p.Start == start
}

// procChain walks from pid up to eight ancestors (a signed commit: ssh-keygen, signing helper, git, shell, agent,
// editor...) and fills in their command lines with one ps call.
func procChain(pid int) []proc {
	var ps []proc
	for i := 0; i < 8 && pid > 1; i++ {
		p, ppid, ok := procInfo(pid)
		if !ok {
			break
		}
		ps = append(ps, p)
		pid = ppid
	}
	if len(ps) == 0 {
		return nil
	}
	var pids []string
	for _, p := range ps {
		pids = append(pids, strconv.Itoa(p.PID))
	}
	// a hanging ps must not hold the request: without its output each process shows its executable
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ps", "-o", "pid=,command=", "-p", strings.Join(pids, ",")).Output()
	args := map[int]string{}
	for _, line := range strings.Split(string(out), "\n") {
		pidS, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if pid, err := strconv.Atoi(pidS); err == nil {
			// ps writes newlines (multi-line commands, commit messages) as \012 and tabs as \011: keep them, so the
			// pages can show a script line by line
			cmd := psUnescape(strings.TrimSpace(rest))
			if len(cmd) > 8000 {
				cmd = cmd[:8000] + "…"
			}
			args[pid] = cmd
		}
	}
	for i := range ps {
		ps[i].Args = args[ps[i].PID]
		if ps[i].Args == "" {
			ps[i].Args = ps[i].Exe
		}
	}
	return ps
}

// peerProcs is the process chain of the client at the other end of a unix socket.
func peerProcs(c *net.UnixConn) []proc { return procChain(peerPID(c)) }

func peerPID(c *net.UnixConn) int {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	if err := raw.Control(func(fd uintptr) { pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) }); err != nil {
		return 0
	}
	return pid
}

func argsOf(ps []proc) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Args
	}
	return out
}

// psUnescape turns ps's \012 and \011 back into a newline and a tab (older audit lines have them too).
func psUnescape(s string) string {
	return strings.NewReplacer(`\012`, "\n", `\011`, "\t").Replace(s)
}
