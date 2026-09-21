# NanoPi R5S (RK3568) eBPF 内核构建与刷机指南

本仓库分支（`r5s-ebpf`）记录了为 NanoPi R5S 构建支持 **eBPF**（重点满足 [dae](https://github.com/daeuniverse/dae) 透明代理所需的 BTF、kprobe、cls_bpf 等）的完整定制修改、镜像构建及刷机流程。

---

## 一、 核心背景与关键修改点

### 1. 为什么原版镜像无法直接支持 eBPF？
原版固件内核未开启 `CONFIG_DEBUG_INFO_BTF`（缺少 BTF 元数据）以及部分 eBPF 网络过滤钩子，导致基于 eBPF 的工具（如 dae）无法运行。

### 2. 关键坑点：内核膨胀导致分区溢出（`kernel.img too big`）
* **体积激增**：开启 `CONFIG_DEBUG_INFO=y` 和 `CONFIG_DEBUG_INFO_BTF=y` 后，编译出的 `kernel.img` 从原先的 ~34 MB 增大到了 **41.15 MB（43,149,332 字节）**。
* **官方限制**：官方默认给 `kernel` 分区规划的大小为 `0x00014000` 扇区（$81920 \times 512\text{ B} = \mathbf{40\text{ MiB}}$）。
* **报错现象**：$41.15\text{ MiB} > 40\text{ MiB}$，在将安装卡插入 R5S 时，板载 `eflasher` 刷机程序会因容量不足报错：
  ```text
  Error: Image file debian-trixie-core-arm64/kernel.img too big.
  ```
* **彻底修复（模板持久化）**：
  构建脚本 `build-kernel.sh` 打包时会自动读取 `prebuilt/parameter.template` 重新生成目标目录的 `parameter.txt`。如果只修改解压后的 `parameter.txt`，会被构建脚本静默还原。因此本分支直接修改了 `prebuilt/` 下的模板文件：
  * 将 `kernel` 分区大小从 `0x00014000`（40 MiB）扩容至 `0x00015000`（42 MiB）。
  * 顺延后续所有分区（boot、recovery、rootfs、userdata）的起始地址 `+0x1000`（2 MiB）：
    ```text
    CMDLINE: mtdparts=rk29xxnand:0x00002000@0x00004000(uboot),0x00002000@0x00006000(misc),0x00002000@0x00008000(dtbo),0x00008000@0x0000a000(resource),0x00015000@0x00012000(kernel),0x00010000@0x00027000(boot),0x00010000@0x00037000(recovery),<ROOTFS_PARTITION_SIZE>@0x00047000(rootfs),-@<USERDATA_PARTITION_ADDR>(userdata:grow)
    ```

### 3. 关键特性移植：TC eBPF `bpf_sk_assign` 原生支持 `SO_REUSEPORT`
* **根因分析**：
  * `dae` 为支持平滑热重载（Same-port zero-downtime reload），默认在监听 socket 上设置了 `SO_REUSEPORT`。
  * 在 Linux 6.5 之前的内核（包括 RK3568 原生的 6.1 LTS）中，`net/core/filter.c` 中的 `bpf_sk_assign` 带有显式限制：
    ```c
    if (unlikely(sk_fullsock(sk) && sk->sk_reuseport))
        return -ESOCKTNOSUPPORT; // 报错 -94
    ```
  * 当 `dae` 在 TC ingress 执行 `bpf_sk_assign` 时会被内核拒绝，导致数据包未成功绑定目标 socket 而进入协议栈引发**静默丢包（典型症状：本机 DNS UDP 53 解析完全超时，curl/ping 域名永久挂起）**。
* **上游特性 Backport**：
  * 完整移植了 Linux 主线（6.5/6.6）由 Lorenz Bauer & Daniel Borkmann 提交的 `SO_REUSEPORT support for TC bpf_sk_assign` 补丁系列核心（Patch 7）。
  * 移除 `bpf_sk_assign` 对 `sk_reuseport` 的阻断限制，在 `skb` 记录 `prefetched` 标记。
  * 传输层解包时通过 `inet_steal_sock()` / `inet6_steal_sock()` 延迟执行 `inet[6]_lookup_reuseport()` 完成监听派发。
  * 引入 `!sk_fullsock(sk)` 边界检查，彻底防御握手期 `request_sock` / `timewait_sock` 引发的 KASAN 内存越界问题。
  * **效果**：原版官方 `dae` 无需任何二进制机器码 Patch 即可直接正常运行。

---

## 二、 仓库改动清单

| 仓库 / 路径 | 分支 | 修改说明 |
| :--- | :--- | :--- |
| **`sd-fuse_rk3568`** | `r5s-ebpf` | |
| ├─ `tools/util.sh` | | 适配 Arch Linux 宿主机：跳过 apt 检查，增加 `aarch64-linux-gnu-gcc` 检测 |
| ├─ `prebuilt/parameter.template` | | kernel 分区从 `0x14000` 扩为 `0x15000`，后置分区偏移顺延 `+0x1000` |
| ├─ `prebuilt/parameter-opt.template` | | 同上（针对带 opt 分区的布局同步修改） |
| └─ `prebuilt/parameter-plain.txt` | | 同上（针对 plain 布局同步修改） |
| **`kernel/`** (子仓库) | `r5s-ebpf` | |
| ├─ `arch/arm64/configs/dae.config` | | 新增内核配置片段（包含 BPF、BTF、kprobe 等必需选项） |
| ├─ `tools/lib/bpf/libbpf.c` | | 修复新版 GCC 下 `next_path` 指针类型的类型不匹配编译告警 |
| ├─ `include/net/sock.h` | | `skb_steal_sock` 增加 `bool *prefetched` 出参，跟踪 BPF 提前挂载状态 |
| ├─ `include/net/inet_hashtables.h` | | 引入 `inet_steal_sock`，实现 IPv4 reuseport 分发并防范 `request_sock` 越界 |
| ├─ `include/net/inet6_hashtables.h` | | 引入 `inet6_steal_sock`，实现 IPv6 reuseport 分发并防范 `request_sock` 越界 |
| ├─ `net/core/filter.c` | | 移除 `bpf_sk_assign` 对 `sk_reuseport` 报错 `-ESOCKTNOSUPPORT` 的限制 |
| └─ `net/ipv[46]/udp.c` | | 将 UDP 接收流程中 `skb_steal_sock` 替换为 `inet[6]_steal_sock` |
---

## 三、 宿主机依赖安装

以 **Arch Linux** 为例：
```bash
sudo pacman -S --needed \
  base-devel git wget rsync \
  bc bison flex openssl elfutils ncurses pahole dtc \
  cpio kmod pigz lz4 swig \
  parted util-linux e2fsprogs btrfs-progs exfatprogs \
  android-tools python perl \
  aarch64-linux-gnu-gcc ccache
```

---

## 四、 编译与镜像构建步骤

### 1. 编译内核并集成到目标 OS
在 `sd-fuse_rk3568` 仓库根目录下执行：
```bash
# 全量重编
KERNEL_SRC="$PWD/kernel" \
KCFG="nanopi5_linux_defconfig kvm.config dae.config" \
./build-kernel.sh debian-trixie-core-arm64

# 或者跳过 distclean 进行增量快编（推荐使用 ccache）：
CROSS_COMPILE="ccache aarch64-linux-gnu-" \
KERNEL_SRC="$PWD/kernel" \
KCFG="nanopi5_linux_defconfig kvm.config dae.config" \
SKIP_DISTCLEAN=1 \
./build-kernel.sh debian-trixie-core-arm64
```
> **注意**：编译完成后脚本会自动挂载并解包 `rootfs.img` 注入新编译的内核模块，该步骤需要 `sudo` 权限，按提示输入密码即可。

### 2. 打包 eMMC 自动刷机镜像
执行以下命令生成全自动烧录镜像（系统开机后会自动将固件刷入板载 eMMC）：
```bash
sudo ./mk-emmc-image.sh debian-trixie-core-arm64 autostart=yes
```
* 构建产物位于：`out/rk3568-eflasher-debian-trixie-core-6.1-arm64-<DATE>.img`。
* **关于镜像大小说明**：
  * 该镜像表观大小为 **7.3 GB**（硬编码虚拟一张 8GB TF 卡的物理分区结构，大部分为空扇区）。
  * 实际磁盘占用（稀疏文件）仅约 **2.4 GB**。
  * 如果需要归档或分发，可用 `pigz -k -9 <img_file>` 压缩，压缩后体积约为 **900 MB**（与官方 release 一致）。


### 3. 打包直接从 SD 卡启动的系统镜像（无需刷入 eMMC，直接运行）
若不想刷机覆写板载 eMMC，而是希望将系统直接运行在 SD 卡上，执行：
```bash
./mk-sd-image.sh debian-trixie-core-arm64
```
* **完全免重新编译**：直接复用 `debian-trixie-core-arm64/` 目录中已编译好的内核与模块，**耗时仅需约 2~3 秒**。
* **无需 root 权限**：不需要 `sudo` 挂载 loop 设备，纯用户态生成。
* 构建产物位于：`out/rk3568-sd-debian-trixie-core-6.1-arm64-<DATE>.img`（实际物理体积仅约 **1.6 GB**）。
* 烧录此镜像后直接插卡开机，板子会直接以 SD 卡为主系统启动运行。
---

## 五、 SD 卡烧录与安全弹出

### 1. 确认 SD 卡设备节点
插入读卡器后，务必先通过 `lsblk` 确认你的 SD 卡设备名（不要盲目写入 `/dev/sdX`，否则会写到内存虚拟文件系统中占用物理 RAM）：
```bash
lsblk -o NAME,SIZE,TYPE,TRAN,RM,MODEL
```
假设确认 SD 卡为 `/dev/sdb`（通常为带有 `TRAN=usb`、`RM=1` 的磁盘）。

### 2. 写入镜像并物理落盘
```bash
# 写入磁盘（请将 /dev/sdb 替换为你真实的 SD 卡设备名）
# 注：conv=fsync 会在 dd 退出前调用系统调用 fsync() 确保所有脏页彻底落盘，无需额外执行 sync
sudo dd if=out/rk3568-eflasher-debian-trixie-core-6.1-arm64-$(date +%Y%m%d).img of=/dev/sdb bs=4M status=progress conv=fsync
```

### 3. 安全弹出设备
确保所有分区已卸载并切断 USB 供电，再物理拔下卡：
```bash
udisksctl power-off -b /dev/sdb
```

---

## 六、 上机安装与验证

1. **上机刷机**：
   * 将 SD 卡插入 NanoPi R5S 的 MicroSD 卡槽。
   * 接通电源开机，系统会自动从 SD 卡启动 eflasher 刷机系统。
   * LED 状态灯会闪烁指示刷机进行中，安装完成后会自动关机或指示灯常亮。
2. **启动系统**：
   * 断开电源，**拔出 SD 卡**。
   * 重新通电，系统将从 eMMC 启动进入 Debian Trixie。
3. **验证 eBPF 与 BTF**：
   ```bash
   # 检查 BTF 文件是否存在
   ls -lh /sys/kernel/btf/vmlinux

   # 检查 BPF 相关编译选项
   zcat /proc/config.gz | grep -E 'CONFIG_BPF|CONFIG_DEBUG_INFO_BTF'

   # 启动 dae 测试
   sudo dae run
   ```
