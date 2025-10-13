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
	"crypto/sha256"
	"encoding/hex"
	"io"
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

func getFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func run(){
	fmt.Printf("MANAGER : Running %v as PID %d\n", os.Args[2:], os.Getpid())

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	mem := flag.CommandLine.Int("m",100,"Memory limit in MB")
	cpu := flag.CommandLine.Int("x",512,"CPU shares (relative weight)")
	ports := flag.String("p", "", "Port mapping hostPort:containerPort")
	flag.CommandLine.Parse(os.Args[2:])

	userCmd := flag.CommandLine.Args()

	bridgeName := "br0"
	gatewayIP := "172.20.0.1/24"

	cidr := "172.20.0.0/24"

	if err := exec.Command("ip", "link", "show", bridgeName).Run(); err != nil {
	    _ = exec.Command("ip", "link", "add", bridgeName, "type", "bridge").Run()
	    _ = exec.Command("ip", "link", "set", bridgeName, "up").Run()
	}

	_ = exec.Command("ip", "addr", "add", gatewayIP, "dev", bridgeName).Run()

	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	_ = exec.Command("sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1").Run()

	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1").Run()
	_ = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.route_localnet=1", bridgeName)).Run()

	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2").Run()
	_ = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=2", bridgeName)).Run()

	if err := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING","-s", cidr, "!", "-o", bridgeName, "-j", "MASQUERADE").Run(); err != nil {
	    _ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
	        "-s", cidr, "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
	}

	if err := exec.Command("iptables", "-C", "FORWARD",
	    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run(); err != nil {
	    _ = exec.Command("iptables", "-A", "FORWARD",
	        "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	}
	if err := exec.Command("iptables", "-C", "FORWARD",
	    "-i", bridgeName, "-j", "ACCEPT").Run(); err != nil {
	    _ = exec.Command("iptables", "-A", "FORWARD", "-i", bridgeName, "-j", "ACCEPT").Run()
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

	if err := os.WriteFile(filepath.Join(containerGroupPath, "memory.max"), []byte(memLimit), 0700); err != nil {
		panic(err)
    }

    if err := os.WriteFile(filepath.Join(containerGroupPath, "cpu.weight"), []byte(cpuLimit), 0700); err != nil {
        panic(err)
    }

    if err := os.WriteFile(filepath.Join(containerGroupPath, "memory.swap.max"), []byte("0"), 0700); err != nil {
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
	
	    if err := exec.Command("iptables", "-t", "nat", "-C", "PREROUTING",
	        "-p", "tcp", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run(); err != nil {
	        _ = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
	            "-p", "tcp", "--dport", hostPort,
	            "-j", "DNAT", "--to-destination", dnatTarget).Run()
	    }

	    defer exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
	        "-p", "tcp", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run()

	    if err := exec.Command("iptables", "-t", "nat", "-C", "OUTPUT",
	        "-p", "tcp", "-d", "127.0.0.1", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run(); err != nil {
	        _ = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
	            "-p", "tcp", "-d", "127.0.0.1", "--dport", hostPort,
	            "-j", "DNAT", "--to-destination", dnatTarget).Run()
	    }
	    defer exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
	        "-p", "tcp", "-d", "127.0.0.1", "--dport", hostPort,
	        "-j", "DNAT", "--to-destination", dnatTarget).Run()


	    if err := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
	        "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	        "-j", "MASQUERADE").Run(); err != nil {
	        _ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
	            "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	            "-j", "MASQUERADE").Run()
	    }
	    defer exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
	        "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	        "-j", "MASQUERADE").Run()

		if err := exec.Command("iptables", "-C", "FORWARD",
	        "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	        "-j", "ACCEPT").Run(); err != nil {
	        _ = exec.Command("iptables", "-A", "FORWARD",
	            "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	            "-j", "ACCEPT").Run()
	    }
	    defer exec.Command("iptables", "-D", "FORWARD",
	        "-p", "tcp", "-d", containerIPNM, "--dport", containerPort,
	        "-j", "ACCEPT").Run()	    
	}

	imagePath := "./images/ubuntu-base.tar.gz"
	imageHash, err := getFileHash(imagePath)
	if err != nil {
		panic("could not hash image file")
	}

	imageStorePath := "/var/lib/pocketdock/images"
	sharedLowerDir := filepath.Join(imageStorePath, imageHash)

	// fmt.Println("sudo tar -xzf",imagePath, "-C", sharedLowerDir)

	if _, err := os.Stat(sharedLowerDir); os.IsNotExist(err) {
		fmt.Println("Image not found in store, unpacking...")
		if err := os.MkdirAll(sharedLowerDir, 0755); err != nil {
			panic(err)
		}
		if err := exec.Command("tar", "-xzf", imagePath, "-C", sharedLowerDir).Run(); err != nil {
			defer os.RemoveAll(sharedLowerDir)
			panic(err)
		}
	}

	tempDir, err := os.MkdirTemp("", "pocketdock-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	upperDir := filepath.Join(tempDir, "upper")
	workDir := filepath.Join(tempDir, "work")
	mergedDir := filepath.Join(tempDir, "merged")

	os.MkdirAll(upperDir, 0755)
	os.MkdirAll(workDir, 0755)
	os.MkdirAll(mergedDir, 0755)
	defer syscall.Unmount(mergedDir,0)
	
	cmd.Env = append(os.Environ(),
		"START_FD=3",
		fmt.Sprintf("POCKETDOCK_VETH=%s", vethContainer),
		fmt.Sprintf("POCKETDOCK_IP=%s", containerIP),
		fmt.Sprintf("POCKETDOCK_MERGED_DIR=%s", mergedDir),
		fmt.Sprintf("POCKETDOCK_LOWER_DIR=%s", sharedLowerDir),
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
	mergedDir := os.Getenv("POCKETDOCK_MERGED_DIR")
	lowerDir := os.Getenv("POCKETDOCK_LOWER_DIR")
	
	gatewayIP := "172.20.0.1"

	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		fmt.Println("lo error -> ",err)
	}
	if err := exec.Command("ip", "link", "set", vethName, "up").Run(); err != nil {
		fmt.Println("veth1 error -> ", err)
	}
	if err := exec.Command("ip", "addr", "add", containerIP, "dev", vethName).Run(); err != nil {
		fmt.Println(containerIP, vethName)
		fmt.Println("error in adding ip to veth1 -> ",err)
	}
	if err := exec.Command("ip", "route", "add", "default", "via", gatewayIP).Run(); err != nil {
		fmt.Println("error in making default gate -> ",err)
	}

	upperDir := filepath.Join(filepath.Dir(mergedDir), "upper")
	workDir := filepath.Join(filepath.Dir(mergedDir), "work")

	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerDir, upperDir, workDir)
	
	if err := syscall.Mount("overlay", mergedDir, "overlay", 0, opts); err != nil {
		panic(err)
	}

	syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")

	syscall.Sethostname([]byte("container"))

	syscall.Chroot(mergedDir)

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
