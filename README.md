```bash
sudo debootstrap --include=iproute2,iputils-ping,net-tools,curl,vim,procps \
  noble /home/ubuntu/rootfs http://archive.ubuntu.com/ubuntu/
```

```bash
sudo tar -czf ubuntu-base.tar.gz -C ~/rootfs .
```
