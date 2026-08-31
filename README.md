# kkk

## Runtime contract

The module exposes a Netlink control plane on the first available protocol in
the range `25..29`:

- `CMD_PING` (`0x1005`) -> `CMD_PONG` (`0x1006`)
- `CMD_HBP_INSTALL` (`0x1001`) -> `CMD_HBP_ACK` (`0x1007`)
- `CMD_STATUS` (`0x1008`) -> `CMD_STATUS_ACK` (`0x1009`)
- `CMD_MEM_READ` (`0x1003`) -> `CMD_MEM_READ_ACK` (`0x1004`); reads are
  limited to the registered thread group and at most 4096 bytes.
- `CMD_HBP_CLEANUP` (`0x1002`)

INSTALL validates the request and holds a reference to the target `mm_struct`.
It does not patch kernel text, alter user PTEs, or redirect page-fault returns.
The optional `do_page_fault` kprobe only increments `hit_count` for the
registered thread group and never changes execution.

Build with the Android kernel tree selected through `KDIR`:

```sh
make KDIR=/path/to/android/kernel
```
