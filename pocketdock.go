package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"flag"
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

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	mem := flag.CommandLine.Int("memory",100,"Memory limit in MB")
	cpu := flag.CommandLine.Int("cpu",512,"CPU shares (relative weight)")
	flag.CommandLine.Parse(os.Args[2:])

	userCmd := flag.CommandLine.Args()
	
	cgroupPath := "/sys/fs/cgroup/pocketdock"
	containerGroupPath := filepath.Join(cgroupPath, "container1")

	if err := os.MkdirAll(containerGroupPath, 0755); err != nil {
		panic(err)
	}
	defer os.RemoveAll(cgroupPath)

	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.subtree_control"), []byte("+cpu +memory"), 0700); err != nil {
		panic(err)
	}

	//This was a mistake to set limits in the leaf node
	//if err := os.WriteFile(filepath.Join(containerGroupPath, "memory.max"), []byte("104857600"), 0700); err != nil {
	//	panic(err)
	//}
	//
	//if err := os.WriteFile(filepath.Join(containerGroupPath, "memory.swap.max"), []byte("0"), 0700); err != nil {
	//	panic(err)
	//}

	memLimit := strconv.Itoa(*mem*1024*1024)
	cpuLimit := strconv.Itoa(*cpu)

	if *cpu>512 {
		cpuLimit = "512"
	}

	if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(memLimit), 0700); err != nil {
		panic(err)
    }

    if err := os.WriteFile(filepath.Join(cgroupPath, "cpu.weight"), []byte(cpuLimit), 0700); err != nil {
        panic(err)
    }

	// optional to make the swap memory limit to 0
    if err := os.WriteFile(filepath.Join(cgroupPath, "memory.swap.max"), []byte("0"), 0700); err != nil {
        panic(err)
    }

	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()

	fmt.Println(userCmd)
	
	args := append([]string{"child"}, userCmd...)

	fmt.Println(args)
	cmd := exec.Command("/proc/self/exe", args...)

	cmd.ExtraFiles = []*os.File{r}
	cmd.Env = append(os.Environ(), "START_FD=3")

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWCGROUP,
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}

	childPID := strconv.Itoa(cmd.Process.Pid)
	fmt.Printf("CHILD PID -> %v\n",childPID)

	if err := os.WriteFile(filepath.Join(containerGroupPath, "cgroup.procs"), []byte(childPID), 0700); err != nil {
		fmt.Println("Error -> ",err)
	    panic(err)
	}

	w.Write([]byte{1})
	w.Close()

	cmd.Wait()
}

func child(){
	fmt.Printf("Child: Running command %v\n", os.Args[2:])

	if fdStr := os.Getenv("START_FD"); fdStr != "" {
		f := os.NewFile(uintptr(3), "start")
		b := []byte{0}
		_, _ = f.Read(b)
		_ = f.Close()
	}

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
