package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	// "io"
	"path/filepath"
	"strconv"
)

func main() {
	switch os.Args[1] {
	case "run":
		run()	
	case "child":
		child()
	default:
		panic("Invalid Command")
	}	
}

func run(){
	fmt.Printf("MANAGER : Running %v as PID %d\n", os.Args[2:], os.Getpid())

	cgroupPath := "/sys/fs/cgroup/pocketdock"
	containerGroupPath := filepath.Join(cgroupPath, "container1")

	if err := os.MkdirAll(containerGroupPath, 0755); err != nil {
		panic(err)
	}
	defer os.RemoveAll(cgroupPath)

	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.subtree_control"), []byte("+cpu +memory"), 0700); err != nil {
		panic(err)
	}

	if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("10000"), 0700); err != nil {
		panic(err)
	}

	args := append([]string{"child"}, os.Args[2:]...)
	cmd := exec.Command("/proc/self/exe", args...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}

	childPID := strconv.Itoa(cmd.Process.Pid)
	fmt.Printf("CHILD PID -> %v\n",childPID)

	if err := os.WriteFile(filepath.Join(containerGroupPath, "cgroup.procs"), []byte(childPID), 0700); err != nil {
	    panic(err)
	}

	cmd.Wait()
}

func child(){
	fmt.Printf("Child: Running command %v\n", os.Args[2:])

	syscall.Mount("","/","",syscall.MS_REC|syscall.MS_PRIVATE,"")

	syscall.Sethostname([]byte("container"))

	jailDir := "/home/ubuntu/my-jail"
	syscall.Chroot(jailDir)

	os.Chdir("/")

	syscall.Mount("proc", "proc", "proc", 0, "")

	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("ERROR:", err)
		syscall.Unmount("proc", 0)
		os.Exit(1)
	}

	syscall.Unmount("proc", 0)
}
