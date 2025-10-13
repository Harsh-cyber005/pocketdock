# Pocketdock

A tiny, educational container runtime in Go.  
Pocketdock shows how Docker-style containers are built from first principles using **Linux namespaces**, **cgroups v2**, **OverlayFS**, and **iptables**.

---

## ✨ Features

- UTS, PID, Mount, CGroup, and NET namespaces
- OverlayFS root filesystem (read-only base + writable upper/work)
- Cgroups v2 limits (CPU weight, memory, swap off)
- Linux bridge (`br0`) + veth pairs for container networking
- Outbound internet via NAT (MASQUERADE)
- Port publishing (`-p host:container`) using DNAT + hairpin MASQUERADE
- Minimal runtime state (`runtime.json`)

---

## 📦 Requirements

- Linux kernel with namespaces, cgroups v2, overlayfs
- Root privileges (or equivalent capabilities)
- Tools in `PATH`: `ip`, `iptables`, `tar`, `modprobe`, `sysctl`, `ss`
- Kernel modules: `overlay`, `br_netfilter`
- Debian/Ubuntu setup:
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential golang iproute2 iptables tar
  ```

## 🔧 Build

  ```bash
  git clone https://github.com/Harsh-cyber005/pocketdock.git
  cd pocketdock
  go build -o pocketdock .
  ```

## 🗂️ Base Image 

Pocketdock expects a minimal rootfs tarball. Place it at /home/ubuntu/ubuntu-base.tar.gz (the path used by the code):
  ```bash
  mkdir -p ./images
  cd ./images
  wget -c -O ./images/ubuntu-base.tar.gz \
    'https://harshmax-vercel-outputs.s3.ap-south-1.amazonaws.com/ubuntu-base.tar.gz'
  ```

## 🚀 Quick Start

Interactive shell inside a container:
  ```bash
  sudo ./pocketdock run /bin/bash
  ```
Basic checks inside the container:
  ```bash
  ip addr
  ip route
  ping -c1 8.8.8.8
  ```
