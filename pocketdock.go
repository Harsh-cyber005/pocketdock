package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"flag"
	"path/filepath"
	"strconv"
	"encoding/json"
	"strings"
)

type Runtime struct {
	ContainerCount int `json:"containerCount"`
}

func readRuntime(runtime *Runtime) {
	cwd, err := os.Getwd()
	if err != nil {
        fmt.Println("Error:", err)
        return
	}
	stateRuntimeFilePath := filepath.Join(cwd, "runtime.json")
    data, err := os.ReadFile(stateRuntimeFilePath)
    if err != nil {
        if os.IsNotExist(err) {
            runtime.ContainerCount = 0
            b, _ := json.MarshalIndent(runtime, "", "  ")
            _ = os.WriteFile(stateRuntimeFilePath, b, 0644)
        } else {
            panic(err)
        }
    } else {
 		_ = json.Unmarshal(data, runtime)
    }
}

func updateRuntime(runtime *Runtime, del int, path string, cgroupPath string) {
	readRuntime(runtime)
	runtime.ContainerCount = runtime.ContainerCount + del
	data, err := json.MarshalIndent(runtime, "", "  ")
	if err != nil {
	    panic(err)
	}
	err = os.WriteFile(path, data, 0644)
	if err != nil {
	    panic(err)
	}
	if runtime.ContainerCount == 0 {
		os.RemoveAll(cgroupPath)
	}
}

func cleanupFunction(containerGroupPath string, runtime *Runtime){
	os.RemoveAll(containerGroupPath)
}

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
	ports := flag.String("p", "", "Port mapping hostPort:containerPort")
	flag.CommandLine.Parse(os.Args[2:])

	userCmd := flag.CommandLine.Args()

	bridgeName := "br0"
	gatewayIP := "172.20.0.1/24"

	if err := exec.Command("ip", "link", "show", bridgeName).Run(); err != nil {
		fmt.Println("Bridge not found, creating and configuring it...")
		exec.Command("ip", "link", "add", bridgeName, "type", "bridge").Run()
		exec.Command("ip", "addr", "add", gatewayIP, "dev", bridgeName).Run()
		exec.Command("ip", "link", "set", bridgeName, "up").Run()
		exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
		exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "172.20.0.0/24", "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
		defer exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "172.20.0.0/24", "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
	}

	var runtime Runtime
	readRuntime(&runtime)

	containerID := "container"+ strconv.Itoa(runtime.ContainerCount+1)
	
	cgroupPath := "/sys/fs/cgroup/pocketdock"
	containerGroupPath := filepath.Join(cgroupPath, containerID)

	if err := os.MkdirAll(containerGroupPath, 0755); err != nil {
		panic(err)
	}
	cwd, err := os.Getwd()
    if err != nil {
	    fmt.Println("Error:", err)
	    return
    }
    stateRuntimeFilePath := filepath.Join(cwd, "runtime.json")
	defer cleanupFunction(containerGroupPath, &runtime)
	defer updateRuntime(&runtime, -1, stateRuntimeFilePath, cgroupPath)

	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.subtree_control"), []byte("+cpu +memory"), 0700); err != nil {
		panic(err)
	}

	memLimit := strconv.Itoa(*mem*1024*1024)
	cpuLimit := strconv.Itoa(*cpu)
	mappings := strings.Split(*ports, ",")

	if *cpu>512 {
		cpuLimit = "512"
	}

	if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(memLimit), 0700); err != nil {
		panic(err)
    }

    if err := os.WriteFile(filepath.Join(cgroupPath, "cpu.weight"), []byte(cpuLimit), 0700); err != nil {
        panic(err)
    }

    if err := os.WriteFile(filepath.Join(cgroupPath, "memory.swap.max"), []byte("0"), 0700); err != nil {
        panic(err)
    }

	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	
	args := append([]string{"child"}, userCmd...)

	cmd := exec.Command("/proc/self/exe", args...)

	cmd.ExtraFiles = []*os.File{r}
	pid := os.Getpid()

	vethHost := fmt.Sprintf("veth0%d", pid)
	vethContainer := fmt.Sprintf("veth1%d", pid)
	if err:=exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethContainer).Run(); err != nil {
		fmt.Println("Error in creating veths -> ",err)
	}
	defer exec.Command("ip", "link", "delete", vethHost).Run()

	if err := exec.Command("ip", "link", "set", vethHost, "master", bridgeName).Run(); err != nil {
		fmt.Printf("Error in making connecting %v to %v -> %v\n",vethHost, bridgeName, err)
	}
 	if err := exec.Command("ip", "link", "set", vethHost, "up").Run(); err != nil {
 		fmt.Println("Error in activating ", vethHost, " -> ", err)
 	}
	containerIP := fmt.Sprintf("172.20.0.%d/24", runtime.ContainerCount+2)

	// these were the DNAT rules:
	
	containerIPNM := fmt.Sprintf("172.20.0.%d", runtime.ContainerCount+2)

	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	for _, mapping := range mappings {
	    if mapping == "" {
	        continue
	    }
	    parts := strings.Split(mapping, ":")
	    if len(parts) != 2 {
	        fmt.Println("Invalid port mapping:", mapping)
	        continue
	    }
	    hostPort := parts[0]
	    containerPort := parts[1]
	    dnatTarget := fmt.Sprintf("%s:%s", containerIPNM, containerPort)
	
	    exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
	        "-p", "tcp", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run()
	    defer exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
	        "-p", "tcp", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run()
	
	    exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
	        "-p", "tcp", "-d", "127.0.0.1", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run()
	    defer exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
	        "-p", "tcp", "-d", "127.0.0.1", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run()

		exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
	    exec.Command("iptables", "-A", "FORWARD",
	        "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	        "-j", "ACCEPT").Run()
	    defer exec.Command("iptables", "-D", "FORWARD",
	        "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	        "-j", "ACCEPT").Run()
	}

	cmd.Env = append(os.Environ(),
		"START_FD=3",
		fmt.Sprintf("POCKETDOCK_VETH=%s", vethContainer),
		fmt.Sprintf("POCKETDOCK_IP=%s", containerIP),
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWCGROUP | syscall.CLONE_NEWNET,
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}

	childPID := strconv.Itoa(cmd.Process.Pid)


	if err := os.WriteFile(filepath.Join(containerGroupPath, "cgroup.procs"), []byte(childPID), 0700); err != nil {
		fmt.Println("Error -> ",err)
	    panic(err)
	}


	if err := exec.Command("ip", "link", "set", vethContainer, "netns", childPID).Run(); err != nil {
		fmt.Println("Error in sending ", vethContainer, " to child ", childPID)
	}

	w.Write([]byte{1})
	w.Close()


	updateRuntime(&runtime, 1, stateRuntimeFilePath, cgroupPath)

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

	vethName := os.Getenv("POCKETDOCK_VETH")
	containerIP := os.Getenv("POCKETDOCK_IP")
	
	gatewayIP := "172.20.0.1"

	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		fmt.Println("lo error -> ",err)
	}
	if err := exec.Command("ip", "link", "set", vethName, "up").Run(); err != nil {
		fmt.Println("veth1 error -> ", err)
	}
	if err := exec.Command("ip", "addr", "add", containerIP, "dev", vethName).Run(); err != nil {
		fmt.Println("error in adding ip to veth1 -> ",err)
	}
	if err := exec.Command("ip", "route", "add", "default", "via", gatewayIP).Run(); err != nil {
		fmt.Println("error in making default gate -> ",err)
	}


	syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")

	syscall.Sethostname([]byte("container"))

	jailDir := "/home/ubuntu/my-jail"
	syscall.Chroot(jailDir)

	os.Chdir("/")

	os.Mkdir("/etc", 0755)
	os.WriteFile("/etc/resolv.conf", []byte("nameserver 8.8.8.8"), 0644)
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
