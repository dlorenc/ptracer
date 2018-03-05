package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	sec "github.com/seccomp/libseccomp-golang"
)

var syscalls = map[int64]bool{
	syscall.SYS_OPEN:   true,
	syscall.SYS_OPENAT: true,
}

type abspath string

func MakeAbs(path string, wd string) abspath {
	if filepath.IsAbs(path) {
		return abspath(path)
	}
	return abspath(filepath.Join(wd, path))
}

var files = map[abspath]struct{}{}

func main() {
	var regs syscall.PtraceRegs

	fmt.Printf("Run %v\n", os.Args[1:])

	// Uncommenting this will cause the open syscall to return with Operation Not Permitted error
	// disallow("open")

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	cmd.Start()
	err := cmd.Wait()
	if err != nil {
		fmt.Printf("Wait returned: %v\n", err)
	}

	parentPid := cmd.Process.Pid
	exit := true

	if err := syscall.PtraceSetOptions(parentPid, syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK|syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACEEXEC|syscall.PTRACE_O_TRACEEXIT); err != nil {
		panic(err)
	}

	processState := map[int]bool{}
	processState[parentPid] = exit

	currentPid := parentPid
loop:
	for {
		if err := syscall.PtraceSyscall(currentPid, 0); err != nil {
			panic(err)
		}

		var wstatus syscall.WaitStatus
		if currentPid, err = syscall.Wait4(-1, &wstatus, 0, nil); err != nil {
			panic(err)
		}

		switch wstatus >> 16 {
		case syscall.PTRACE_EVENT_CLONE:
			fmt.Println("clone")
			evt, _ := syscall.PtraceGetEventMsg(currentPid)
			fmt.Println("New pid: ", evt)
		case syscall.PTRACE_EVENT_EXEC:
			fmt.Println("exec")
		case syscall.PTRACE_EVENT_EXIT:
			fmt.Println("exit")
			evt, _ := syscall.PtraceGetEventMsg(currentPid)
			fmt.Println("Status: ", evt)
			break loop
		case syscall.PTRACE_EVENT_FORK:
			fmt.Println("fork")
			evt, _ := syscall.PtraceGetEventMsg(currentPid)
			fmt.Println("New pid: ", evt)
		case syscall.PTRACE_EVENT_VFORK:
			fmt.Println("vfork")
			evt, _ := syscall.PtraceGetEventMsg(currentPid)
			fmt.Println("New pid: ", evt)
		case syscall.PTRACE_EVENT_VFORK_DONE:
			fmt.Println("vfork done")
			evt, _ := syscall.PtraceGetEventMsg(currentPid)
			fmt.Println("New pid: ", evt)
		}

		processState[currentPid] = !processState[currentPid]

		if processState[currentPid] {
			err = syscall.PtraceGetRegs(currentPid, &regs)
			if err != nil {
				break
			}
			name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()

			if _, ok := syscalls[int64(regs.Orig_rax)]; ok {
				path := peekString(currentPid, uintptr(regs.Rdi))
				flags := regs.Rsi
				if flags&uint64(os.O_WRONLY|os.O_RDWR) != 0 {
					wd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", currentPid))
					absPath := MakeAbs(path, wd)
					files[absPath] = struct{}{}
					fmt.Println(name, currentPid, absPath)
				}
			}
		}
	}
}

func peekString(pid int, addr uintptr) string {
	var bytes []byte
	buf := make([]byte, 16)
	for {
		n, _ := syscall.PtracePeekData(pid, addr, buf)
		addr = addr + 16
		if n < 8 {
			bytes = append(bytes, buf[:n]...)
			return string(bytes)
		}
		for n, b := range buf {
			if b == '\x00' {
				bytes = append(bytes, buf[:n]...)
				return string(bytes)
			}
		}
		bytes = append(bytes, buf...)
	}
}

func fd2path(fd int, pid int) (string, error) {
	return os.Readlink(filepath.Join("/proc", string(pid), "fd", string(fd)))
}
