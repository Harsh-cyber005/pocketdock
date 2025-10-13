package network

import (
	"fmt"
	"os/exec"
)

const (
	DefaultBridge   = "br0"
	DefaultGatewayCidr = "172.20.0.1/24"
	DefaultCIDR     = "172.20.0.0/24"
)

func EnsureBridge(bridgeName, gatewayCIDR string) {
	if bridgeName == "" { bridgeName = DefaultBridge }
	if gatewayCIDR == "" { gatewayCIDR = DefaultGatewayCidr }

	if err := exec.Command("ip", "link", "show", bridgeName).Run(); err != nil {
		_ = exec.Command("ip", "link", "add", bridgeName, "type", "bridge").Run()
		_ = exec.Command("ip", "link", "set", bridgeName, "up").Run()
	}
	_ = exec.Command("ip", "addr", "add", gatewayCIDR, "dev", bridgeName).Run()

	// sysctls helpful for forwarding / filtering
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1").Run()
	_ = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.route_localnet=1", bridgeName)).Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2").Run()
	_ = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=2", bridgeName)).Run()
}

func CreateVethPair(pid int) (hostIf, childIf string, _ error) {
	hostIf = fmt.Sprintf("veth0%d", pid)
	childIf = fmt.Sprintf("veth1%d", pid)
	return hostIf, childIf, exec.Command("ip", "link", "add", hostIf, "type", "veth", "peer", "name", childIf).Run()
}

func AddVethToBridge(hostIf, bridgeName string) {
	if bridgeName == "" { bridgeName = DefaultBridge }
	_ = exec.Command("ip", "link", "set", hostIf, "master", bridgeName).Run()
	_ = exec.Command("ip", "link", "set", hostIf, "up").Run()
}

func MoveIntoNetNS(childIf, childPID string) {
	_ = exec.Command("ip", "link", "set", childIf, "netns", childPID).Run()
}

func BringUpLoopbackChild() { _ = exec.Command("ip", "link", "set", "lo", "up").Run() }

func BringUpChildVeth(childIf string) { _ = exec.Command("ip", "link", "set", childIf, "up").Run() }

func AssignChildIP(childIf, cidr string) {
	_ = exec.Command("ip", "addr", "add", cidr, "dev", childIf).Run()
}

func SetDefaultRoute(gatewayIP string) {
	_ = exec.Command("ip", "route", "add", "default", "via", gatewayIP).Run()
}
