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

	pid := cmd.Process.Pid
	exit := true

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}
			name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
			fmt.Printf("%s\n", name)

			if _, ok := syscalls[int64(regs.Orig_rax)]; ok {
				path := peekString(pid, uintptr(regs.Rdi))
				if !filepath.IsAbs(path) {
					wd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
					path = filepath.Join(wd, path)
				}
				fmt.Println(name)
				fmt.Println(path)
			}
		}

		if regs.Orig_rax == syscall.SYS_EXIT || regs.Orig_rax == syscall.SYS_EXIT_GROUP {
			break
		}

		if err := syscall.PtraceSyscall(pid, 0); err != nil {
			panic(err)
		}

		if _, err := syscall.Wait4(pid, nil, 0, nil); err != nil {
			panic(err)
		}

		exit = !exit
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
