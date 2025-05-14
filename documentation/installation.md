## Launch VMS

### Go to VM folder
```bash
cd VMS
```
### Launch victime VM

```bash
qemu-system-x86_64 -m 2048 \
  -enable-kvm \
  -drive file=debian9-victim.qcow2,format=qcow2,if=virtio \
  -boot order=c \
  -nic user,model=virtio \
  -display sdl
```

### Enter credentials
user: victime
password: to_enter_later
