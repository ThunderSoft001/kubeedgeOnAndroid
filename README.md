# RK3568 Android运行KubeEdge

以firefly rk3568为例，展示Android设备上运行KubeEdge的具体过程。这里，KubeEdge所用的运行时为docker；使用containerd运行时，所需步骤类似。

## Android运行Docker容器关键步骤说明

1. ### 准备支持Docker容器的Android内核；

   a. 修改内核配置：cgroup和namespace相关特性；
   b. 修改内核cpuset；

确保docker容器使用的cpuset节点存在于Android系统中；

   c. 创建docker运行所需文件目录结构；

docker运行需要一些目录，但是Android根目录是只读的，无法在根目录下创建目录，所以在编译镜像时就创建好这些目录：run var tmp opt usr

   d. 修改network

Android 默认是 "Only specific groups can create sockets"。需要修改Android paranoid network中的CONFIG_ANDROID_PARANOID_NETWORK参数。修改目标效果是"all groups can create sockets"。

Android网络缺省设置支持不支持网络包forward，需要回避解决。

   e. 修改overlay filesystem

在Android系统overlay filesystem推荐backing filesystem是未加密的f2fs。

2. ### 编译并在设备上安装Android系统

3. ### 安装Docker容器引擎组件

将docker静态二进制文件拷贝到Android设备 /system/bin/ 目录下，并添加执行权限



4. ### 挂载Android系统资源

修改安卓操作系统的/etc/cgroups.json文件，挂载所有的cgroup子系统。

5. ### 环境准备操作

   a. 创建docker运行所需目录

```Bash
mkdir /var
mkdir /run
mkdir /tmp
mkdir /opt
mkdir /usr
mkdir /data/var
mkdir /data/run
mkdir /data/tmp
mkdir /data/opt
mkdir /data/etc
mkdir /data/etc/docker
mkdir /data/usr
mkdir /data/bin
mkdir /data/root
```

   b. 挂载docker所需目录

```Shell
mount tmpfs /sys/fs/cgroup -t tmpfs -o size=1G
mkdir /sys/fs/cgroup/blkio
mkdir /sys/fs/cgroup/cpu
mkdir /sys/fs/cgroup/cpuacct
mkdir /sys/fs/cgroup/cpuset
mkdir /sys/fs/cgroup/devices
mkdir /sys/fs/cgroup/freezer
mkdir /sys/fs/cgroup/hugetlb
mkdir /sys/fs/cgroup/memory
mkdir /sys/fs/cgroup/net_cls
mkdir /sys/fs/cgroup/net_prio
mkdir /sys/fs/cgroup/perf_event
mkdir /sys/fs/cgroup/pids
mkdir /sys/fs/cgroup/rdma
mkdir /sys/fs/cgroup/schedtune
mkdir /sys/fs/cgroup/systemd
# mount --bind
mount --bind /data/etc/docker /etc/docker
mount --bind /data/var /var
mount --bind /data/run /run
mount --bind /data/tmp /tmp
mount --bind /data/opt /opt
mount --bind /data/usr /usr
mount --bind /data/bin /bin
mount --bind /data/root /root
#mount cgroup
mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd
mount -t cgroup -o blkio,nodev,noexec,nosuid cgroup /sys/fs/cgroup/blkio
mount -t cgroup -o cpu,nodev,noexec,nosuid cgroup /sys/fs/cgroup/cpu
mount -t cgroup -o cpuacct,nodev,noexec,nosuid cgroup /sys/fs/cgroup/cpuacct
mount -t cgroup -o cpuset,nodev,noexec,nosuid cgroup /sys/fs/cgroup/cpuset
mount -t cgroup -o devices,nodev,noexec,nosuid cgroup /sys/fs/cgroup/devices
mount -t cgroup -o freezer,nodev,noexec,nosuid cgroup /sys/fs/cgroup/freezer
mount -t cgroup -o hugetlb,nodev,noexec,nosuid cgroup /sys/fs/cgroup/hugetlb
mount -t cgroup -o memory,nodev,noexec,nosuid cgroup /sys/fs/cgroup/memory
mount -t cgroup -o net_cls,nodev,noexec,nosuid cgroup /sys/fs/cgroup/net_cls
mount -t cgroup -o net_prio,nodev,noexec,nosuid cgroup /sys/fs/cgroup/net_prio
mount -t cgroup -o perf_event,nodev,noexec,nosuid cgroup /sys/fs/cgroup/perf_event
mount -t cgroup -o pids,nodev,noexec,nosuid cgroup /sys/fs/cgroup/pids
mount -t cgroup -o rdma,nodev,noexec,nosuid cgroup /sys/fs/cgroup/rdma
mount -t cgroup -o schedtune,nodev,noexec,nosuid cgroup /sys/fs/cgroup/schedtune
```

   c. 添加路由规则

```Shell
ip rule add pref 1 from all lookup main
ip rule add pref 2 from all lookup default
```

   d. 关闭selinux

```Shell
setenforce 0
```

   e. 创建文件 /etc/docker/daemon.json 写入

```Plain%20Text
{"registry-mirrors":["https://docker.mirrors.ustc.edu.cn"],"experimental":true}
```

6. ### 运行docker

```Shell
dockerd -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock & 
```

7. ### 验证docker工作状态

通过docker自带的helloworld容器镜像验证。请在测试设备可访问外部网络的环境下，执行下面指令。该指令会先在本地搜索'hello-world:latest'容器镜像文件，未找到会从docker默认的网络地址自动下载。

```Shell
docker run hello-world
```

执行该命令后，控制台会看到下列对话：

```Shell
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
93288797bd35: Pull complete 
Digest: sha256:2498fce14358aa50ead0cc6c19990fc6ff866ce72aeb5546e1d59caac3d0d60f
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (arm64v8)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

当出现上图中绿色部分内容，代表docker容器运行成功。



## 在RK3568平台上实现参考

### 环境信息

硬件环境

芯片：RockChip RK3568

开发板： ROC-RK3568-PC四核64位开源主板 

![img](https://thundersoft.feishu.cn/space/api/box/stream/download/asynccode/?code=MjI1OTNlODQyYjY0NGIwMDk3ZGRkNGE2YjczMDI2YmZfUVd6Y0NRSWlrdUYzNzF6ckdPbXlWbjllYVNrZVJiRWJfVG9rZW46Ym94Y25ya2tTdDhlQmc5eWVXTHBNckkzVlRoXzE2NTY5MjIwNjA6MTY1NjkyNTY2MF9WNA)

软件环境

源代码下载：

https://www.t-firefly.com/doc/download/107.html

| 软件名称 | 版本信息 |
| -------- | -------- |
| Docker   | 20.10.9  |
| Android  | 11       |
| Kernel   | 4.19.193 |

### 操作过程与参考文件

1. #### 修改kernel/arch/arm64/configs/firefly_defconfig，

主要集中在namespace, control group, network, overlay filesystem等方面支持的追加。



把android /proc/config.gz pull到linux, 用下面的script check一下支持docker(containerd)尚有哪些不足。

https://github.com/moby/moby/blob/master/contrib/check-config.sh

./check-config.sh ./config.gz



修改后文件内容如下：

```Bash
diff --git a/kernel/arch/arm64/configs/firefly_defconfig b/kernel/arch/arm64/configs/firefly_defconfig
index 57ed787337..01083bc496 100644
--- a/kernel/arch/arm64/configs/firefly_defconfig
+++ b/kernel/arch/arm64/configs/firefly_defconfig
@@ -24,7 +24,6 @@ CONFIG_CPUSETS=y
 CONFIG_CGROUP_CPUACCT=y
 CONFIG_CGROUP_BPF=y
 CONFIG_NAMESPACES=y
-# CONFIG_PID_NS is not set
 CONFIG_SCHED_TUNE=y
 CONFIG_BLK_DEV_INITRD=y
 # CONFIG_RD_BZIP2 is not set
@@ -978,3 +977,44 @@ CONFIG_MFD_RK628=y
 CONFIG_DRM_ROCKCHIP_RK628=y
 CONFIG_VIDEO_RK628CSI=y
 CONFIG_VIDEO_XC7160=y
+CONFIG_UTS_NS=y
+CONFIG_PID_NS=y
+CONFIG_OVERLAY_FS=y
+CONFIG_CGROUP_PIDS=y
+CONFIG_CGROUP_DEVICE=y
+CONFIG_MEMCG=y
+CONFIG_BLK_CGROUP=y
+CONFIG_CFS_BANDWIDTH=y
+CONFIG_IPC_NS=y
+CONFIG_USER_NS=y
+CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y
+CONFIG_NETFILTER_XTABLES=y
+CONFIG_IP_VS=y
+CONFIG_NETFILTER_ADVANCED=y
+CONFIG_NETFILTER_XT_MATCH_IPVS=y
+CONFIG_NETFILTER_XT_TARGET_CHECKSUM=y
+CONFIG_POSIX_MQUEUE=y
+CONFIG_EXT4_FS_POSIX_ACL=y
+CONFIG_VXLAN=y
+CONFIG_AUFS_FS=y
+CONFIG_IP_SET=y
+CONFIG_IP_SET_HASH_IP=y
+CONFIG_IP_SET_HASH_NET=y
+CONFIG_NETFILTER_XT_SET=y
+CONFIG_SYSVIPC=y
+CONFIG_BLK_DEV_THROTTLING=y
+CONFIG_BINFMT_MISC=y
+CONFIG_NETFILTER_XT_MATCH_CGROUP=y
+CONFIG_IP_VS_PROTO_TCP=y
+CONFIG_IP_VS_PROTO_UDP=y
+CONFIG_IP_VS_RR=y
+CONFIG_IP_VS_NFCT=y
+CONFIG_NET_CLS_CGROUP=y
+CONFIG_CGROUP_NET_PRIO=y
+CONFIG_MACVLAN=y
+CONFIG_IP_VS_WRR=y
+CONFIG_IP_VS_SH=y
+CONFIG_CGROUP_PERF=y
+CONFIG_ANDROID_PARANOID_NETWORK=n
```

2. #### 修改kernel/configs/r/android-4.19/android-base.config，

使得CONFIG_SYSVIPC在此处的支持与上述firefly_defconfig修改一致。

```Delphi
diff --git a/kernel/configs/r/android-4.19/android-base.config b/kernel/configs/r/android-4.19/android-base.config
index f942b8e12e..5636055655 100644
--- a/kernel/configs/r/android-4.19/android-base.config
+++ b/kernel/configs/r/android-4.19/android-base.config
@@ -11,7 +11,7 @@
 # CONFIG_NFS_FS is not set
 # CONFIG_PM_AUTOSLEEP is not set
 # CONFIG_RT_GROUP_SCHED is not set
-# CONFIG_SYSVIPC is not set
+CONFIG_SYSVIPC=y
 # CONFIG_USELIB is not set
 # CONFIG_VHOST is not set
 CONFIG_ADVISE_SYSCALLS=y
```

3. #### 修改kernel/kernel/cgroup/cpuset.c，

保证docker所用cpuset节点在android设备上是存在的。

```Swift
diff --git a/kernel/kernel/cgroup/cpuset.c b/kernel/kernel/cgroup/cpuset.c
index d50a89ccfe..6880b6f0ff 100644
--- a/kernel/kernel/cgroup/cpuset.c
+++ b/kernel/kernel/cgroup/cpuset.c
@@ -1840,7 +1840,7 @@ static s64 cpuset_read_s64(struct cgroup_subsys_state *css, struct cftype *cft)
 
 static struct cftype files[] = {
        {
-               .name = "cpus",
+               .name = "cpuset.cpus",
                .seq_show = cpuset_common_seq_show,
                .write = cpuset_write_resmask,
                .max_write_len = (100U + 6 * NR_CPUS),
@@ -1848,7 +1848,7 @@ static struct cftype files[] = {
        },
 
        {
-               .name = "mems",
+               .name = "cpuset.mems",
                .seq_show = cpuset_common_seq_show,
                .write = cpuset_write_resmask,
                .max_write_len = (100U + 6 * MAX_NUMNODES),
@@ -1856,81 +1856,81 @@ static struct cftype files[] = {
        },
 
        {
-               .name = "effective_cpus",
+               .name = "cpuset.effective_cpus",
                .seq_show = cpuset_common_seq_show,
                .private = FILE_EFFECTIVE_CPULIST,
        },
 
        {
-               .name = "effective_mems",
+               .name = "cpuset.effective_mems",
                .seq_show = cpuset_common_seq_show,
                .private = FILE_EFFECTIVE_MEMLIST,
        },
 
        {
-               .name = "cpu_exclusive",
+               .name = "cpuset.cpu_exclusive",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_CPU_EXCLUSIVE,
        },
 
        {
-               .name = "mem_exclusive",
+               .name = "cpuset.mem_exclusive",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_MEM_EXCLUSIVE,
        },
 
        {
-               .name = "mem_hardwall",
+               .name = "cpuset.mem_hardwall",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_MEM_HARDWALL,
        },
 
        {
-               .name = "sched_load_balance",
+               .name = "cpuset.sched_load_balance",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_SCHED_LOAD_BALANCE,
        },
 
        {
-               .name = "sched_relax_domain_level",
+               .name = "cpuset.sched_relax_domain_level",
                .read_s64 = cpuset_read_s64,
                .write_s64 = cpuset_write_s64,
                .private = FILE_SCHED_RELAX_DOMAIN_LEVEL,
        },
 
        {
-               .name = "memory_migrate",
+               .name = "cpuset.memory_migrate",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_MEMORY_MIGRATE,
        },
 
        {
-               .name = "memory_pressure",
+               .name = "cpuset.memory_pressure",
                .read_u64 = cpuset_read_u64,
                .private = FILE_MEMORY_PRESSURE,
        },
 
        {
-               .name = "memory_spread_page",
+               .name = "cpuset.memory_spread_page",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_SPREAD_PAGE,
        },
 
        {
-               .name = "memory_spread_slab",
+               .name = "cpuset.memory_spread_slab",
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
                .private = FILE_SPREAD_SLAB,
        },
 
        {
-               .name = "memory_pressure_enabled",
+               .name = "cpuset.memory_pressure_enabled",
                .flags = CFTYPE_ONLY_ON_ROOT,
                .read_u64 = cpuset_read_u64,
                .write_u64 = cpuset_write_u64,
```

4. #### 追加docker在Android上正常运行所需的一些目录: run var tmp opt usr等。

修改system/core/rootdir/Android.mk

```Assembly%20language
diff --git a/system/core/rootdir/Android.mk b/system/core/rootdir/Android.mk
index a9d0ed08a9..8e78ef9411 100644
--- a/system/core/rootdir/Android.mk
+++ b/system/core/rootdir/Android.mk
@@ -78,7 +78,7 @@ endif
 # create some directories (some are mount points) and symlinks
 LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
     dev proc sys system data data_mirror odm oem acct config storage mnt apex debug_ramdisk \
-    linkerconfig $(BOARD_ROOT_EXTRA_FOLDERS)); \
+    linkerconfig run var tmp opt usr lib $(BOARD_ROOT_EXTRA_FOLDERS)); \
     ln -sf /system/bin $(TARGET_ROOT_OUT)/bin; \
     ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
     ln -sf /data/user_de/0/com.android.shell/files/bugreports $(TARGET_ROOT_OUT)/bugreports; \
```

修改system/sepolicy/prebuilts/api/30.0/private/file_contexts

```Assembly%20language
diff --git a/system/sepolicy/prebuilts/api/30.0/private/file_contexts b/system/sepolicy/prebuilts/api/30.0/private/file_contexts
index b0e058ae67..027a364dd4 100644
--- a/system/sepolicy/prebuilts/api/30.0/private/file_contexts
+++ b/system/sepolicy/prebuilts/api/30.0/private/file_contexts
@@ -33,6 +33,14 @@
 /sys                u:object_r:sysfs:s0
 /apex               u:object_r:apex_mnt_dir:s0
 
+# for docker
+/run                u:object_r:rootfs:s0
+/var                u:object_r:rootfs:s0
+/tmp                u:object_r:rootfs:s0
+/opt                u:object_r:rootfs:s0
+/usr                u:object_r:rootfs:s0
+/lib                u:object_r:rootfs:s0
 # Symlinks
 /bin                u:object_r:rootfs:s0
 /bugreports         u:object_r:rootfs:s0
```

修改 system/sepolicy/private/file_contexts 文件

```Bash
diff --git a/system/sepolicy/private/file_contexts b/system/sepolicy/private/file_contexts
index b0e058ae67..027a364dd4 100644
--- a/system/sepolicy/private/file_contexts
+++ b/system/sepolicy/private/file_contexts
@@ -33,6 +33,14 @@
 /sys                u:object_r:sysfs:s0
 /apex               u:object_r:apex_mnt_dir:s0
 
+# for docker
+/run                u:object_r:rootfs:s0
+/var                u:object_r:rootfs:s0
+/tmp                u:object_r:rootfs:s0
+/opt                u:object_r:rootfs:s0
+/usr                u:object_r:rootfs:s0
+/lib                u:object_r:rootfs:s0
+
 # Symlinks
 /bin                u:object_r:rootfs:s0
 /bugreports         u:object_r:rootfs:s0
```

5. #### 编译烧写rk3568

6. #### 修改 Docker overlay backing filesystem

RK3568的data分区是加密的ext4。在Android上overlay2 filesystem推荐backing filesystem是未加密的f2fs。

可以通过PCIe接SSD硬盘；或通过micro sd card卡扩展RK3568的存储；或将SSD硬盘或sd card格式化为f2fs解决此问题。

```Apache
使用fdisk，在硬盘或sd card上创建primary partition
blkid
mkfs.f2fs /dev/sdc1 
```

7. #### 解决Android网络问题

首先，需要确认启用了ip forward功能。

```Bash
cat /proc/sys/net/ipv4/ip_forward
1
```

解决android设备不能forward问题。

```Bash
# eth1需要根据设备的实际情况调整
ip route add default via 10.0.20.1 dev eth1
ip rule add from all table eth1 prio 3
# iptables调整
iptables -D tetherctrl_FORWARD 1
```

8. #### 修改安卓操作系统的/etc/cgroups.json文件，

修改为如上的内容，用于挂载所有的cgroup子系统。 

```JSON
{
  "Cgroups": [
    {
      "UID": "system",
      "GID": "system",
      "Mode": "0755",
      "Controller": "blkio",
      "Path": "/dev/blkio"
    },
    {
      "UID": "system",
      "GID": "system",
      "Mode": "0755",
      "Controller": "cpu",
      "Path": "/dev/cpu"
    },
    {
      "Mode": "0555",
      "Path": "/dev/cpuacct",
      "Controller": "cpuacct"
    },
    {
      "UID": "system",
      "GID": "system",
      "Mode": "0755",
      "Controller": "cpuset",
      "Path": "/dev/cpuset"
    },
    {
      "UID": "system",
      "GID": "system",
      "Mode": "0755",
      "Controller": "memory",
      "Path": "/dev/memcg"
    },
    {
      "UID": "system",
      "GID": "system",
      "Mode": "0755",
      "Controller": "schedtune",
      "Path": "/dev/stune"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "devices",
      "Path": "/dev/devices"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "freezer",
      "Path": "/dev/freezer"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "hugetlb",
      "Path": "/dev/hugetlb"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "net_cls",
      "Path": "/dev/net_cls"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "net_prio",
      "Path": "/dev/net_prio"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "perf_event",
      "Path": "/dev/perf_event"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "pids",
      "Path": "/dev/pids"
    },
    {
      "GID": "system",
      "UID": "system",
      "Mode": "0755",
      "Controller": "rdma",
      "Path": "/dev/rdma"
    }
  ],
  "Cgroups2": {
    "UID": "root",
    "GID": "root",
    "Mode": "0600",
    "Path": "/dev/cg2_bpf"
  }
}
```

9. #### 下载docker static binaries，tar zxvf 到/system/bin下

URL    https://download.docker.com/linux/static/stable/aarch64/

若Android系统是arm 32位，注意选择armhf版。



10. #### 执行脚本：

```Bash
# mkdir on /system
if [ ! -d "/system/etc/docker" ]; then
        mkdir /system/etc/docker
fi

# mkdir on /data
if [ ! -d "/data/var" ]; then
        mkdir /data/var
else
        rm -rf /data/var/run
fi
if [ ! -d "/data/run" ]; then
        mkdir /data/run
fi
if [ ! -d "/data/tmp" ]; then
        mkdir /data/tmp
fi
if [ ! -d "/data/opt" ]; then
        mkdir /data/opt
fi
if [ ! -d "/data/etc" ]; then
        mkdir /data/etc
        mkdir /data/etc/docker
fi
if [ ! -d "/data/usr" ]; then
        mkdir /data/usr
fi
if [ ! -d "/mnt/f2fs" ]; then
        mkdir /mnt/f2fs
fi

mount /dev/block/mmcblk0p1 /mnt/f2fs/

mount tmpfs /sys/fs/cgroup -t tmpfs -o size=1G
if [ ! -d "/sys/fs/cgroup/blkio" ]; then
        mkdir /sys/fs/cgroup/blkio
        mkdir /sys/fs/cgroup/cpu
        mkdir /sys/fs/cgroup/cpuacct
        mkdir /sys/fs/cgroup/cpuset
        mkdir /sys/fs/cgroup/devices
        mkdir /sys/fs/cgroup/freezer
        mkdir /sys/fs/cgroup/hugetlb
        mkdir /sys/fs/cgroup/memory
        mkdir /sys/fs/cgroup/net_cls
        mkdir /sys/fs/cgroup/net_prio
        mkdir /sys/fs/cgroup/perf_event
        mkdir /sys/fs/cgroup/pids
        mkdir /sys/fs/cgroup/rdma
        mkdir /sys/fs/cgroup/schedtune
        mkdir /sys/fs/cgroup/systemd
fi

# mount --bind
mount --bind /data/etc/docker /etc/docker
mount --bind /data/var /var
mount --bind /data/run /run
mount --bind /data/tmp /tmp
mount --bind /data/opt /opt
mount --bind /data/usr /usr

mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd
mount -t cgroup -o blkio,nodev,noexec,nosuid cgroup /sys/fs/cgroup/blkio
mount -t cgroup -o cpu,nodev,noexec,nosuid cgroup /sys/fs/cgroup/cpu
mount -t cgroup -o cpuacct,nodev,noexec,nosuid cgroup /sys/fs/cgroup/cpuacct
mount -t cgroup -o cpuset,nodev,noexec,nosuid cgroup /sys/fs/cgroup/cpuset
mount -t cgroup -o devices,nodev,noexec,nosuid cgroup /sys/fs/cgroup/devices
mount -t cgroup -o freezer,nodev,noexec,nosuid cgroup /sys/fs/cgroup/freezer
mount -t cgroup -o hugetlb,nodev,noexec,nosuid cgroup /sys/fs/cgroup/hugetlb
mount -t cgroup -o memory,nodev,noexec,nosuid cgroup /sys/fs/cgroup/memory
mount -t cgroup -o net_cls,nodev,noexec,nosuid cgroup /sys/fs/cgroup/net_cls
mount -t cgroup -o net_prio,nodev,noexec,nosuid cgroup /sys/fs/cgroup/net_prio
mount -t cgroup -o perf_event,nodev,noexec,nosuid cgroup /sys/fs/cgroup/perf_event
mount -t cgroup -o pids,nodev,noexec,nosuid cgroup /sys/fs/cgroup/pids
mount -t cgroup -o rdma,nodev,noexec,nosuid cgroup /sys/fs/cgroup/rdma
mount -t cgroup -o schedtune,nodev,noexec,nosuid cgroup /sys/fs/cgroup/schedtune

# ip route
ip rule add pref 1 from all lookup main
ip rule add pref 2 from all lookup default
###
# setup dns nameserver and docker images registry
echo "{\"registry-mirrors\":[\"https://docker.mirrors.ustc.edu.cn\"],\"experimental\":false,\"storage-driver\": \"overlay2\",\"data-root\": \"/mnt/f2fs\"}" > /etc/docker/daemon.json
# open br_netfilter module
#modprobe br_netfilter
setenforce 0
# run dockerd
dockerd -D -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock &
```

11. #### 测试docker安装正常

```Bash
130|rk3568:/ # docker run hello-world

Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (arm64v8)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

实际执行效果：

![img](https://thundersoft.feishu.cn/space/api/box/stream/download/asynccode/?code=YmU0YzYyYzBjNDQxODYyYWQ5MGQyY2U5MzEyOWMxY2ZfbUozRkZKTG85MkZ5b0IzcHRQWWQzOTk2c0x1c2xwY1JfVG9rZW46Ym94Y25ZcE5BNm1TUkJhTDN0a2RPMmQweXBBXzE2NTY5MjIwNjA6MTY1NjkyNTY2MF9WNA)



### KubeEdge



打通了KubeEdge云与Android边的云边网络service通信。

要点:

1. 使用了KubeEdge v1.10.0 release，同时编译了Android用的static edgecore v1.10.0；
2. 但image kubeedge/edgemesh-{agent,server}使用v1.9.0 tag；v1.10.0 tag出错。
3. 若node spec低，需要注意控制edgemesh-{agent,server} cpu requests量。



#### 云端安装KubeEdge cloudcore

在AliYun VM上安装KubeEdge cloudcore

VM上已安装K3s (or k8s)环境。

```Bash
keadm init --advertise-address="39.100.104.24" --kubeedge-version=1.10.0

git clone https://github.com/kubeedge/edgemesh.git
cd edgemesh/build/helm

# 根据cloud/edge spec, 安装前注意适当修改edgemesh-{agent,server} cpu requests
# image kubeedge/edgemesh-{agent,server}使用v1.9.0 tag, 尽量别用latest
helm install edgemesh \
--set server.nodeName=iz8vb6arhi7qonkkj0168mz \
--set server.advertiseAddress="{39.100.104.24}" \
./edgemesh

keadm gettoken
```



#### EdgeCore static build for Android

在Arm server上编译KubeEdge static edgecore

```Bash
git clone https://github.com/kubeedge/kubeedge.git
cd kubeedge
git checkout tags/v1.10.0

# static
#COPY ./build/edge/tmp/qemu-${QEMU_ARCH}-static /usr/bin/
#COPY --from=builder /usr/bin/qemu* /usr/bin/

docker build -t kubeedge/edgecore:v1.10.0 -f build/edge/Dockerfile .

docker cp $(docker create --rm kubeedge/edgecore:v1.10.0):/usr/local/bin/edgecore ./edgecore.1.10.0
```



#### Edge RK3568 SBC

将static edgecore adb push到RK3568 android /system/bin上

```Bash
mkdir -p /etc/kubeedge/config

cd /etc/kubeedge/config
edgecore --minconfig > edgecore.yaml 

#修改edgecore.yaml大体如下，注意cloud token

#启动edgecore
edgecore
```



#### edgecore.yaml参考

```YAML
# With --minconfig , you can easily used this configurations as reference.
# It's useful to users who are new to KubeEdge, and you can modify/create your own configs accordingly. 
# This configuration is suitable for beginners.
apiVersion: edgecore.config.kubeedge.io/v1alpha1
database:
  dataSource: /var/lib/kubeedge/edgecore.db
kind: EdgeCore
modules:
  edgeHub:
    enable: true
    heartbeat: 15
    httpServer: https://8.142.141.36:10002
    tlsCaFile: /etc/kubeedge/ca/rootCA.crt
    tlsCertFile: /etc/kubeedge/certs/server.crt
    tlsPrivateKeyFile: /etc/kubeedge/certs/server.key
    token: e8ceef8db0cd06fad0cc13c966527eb06b4c09a5f85818635b2a777ea915945d.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTY5NDQ5MzV9.ff38T0LnXpJEdndfSvOuUUofG-5umKQY0IZ36_MFAOs
    websocket:
      enable: true
      handshakeTimeout: 30
      readDeadline: 15
      server: 8.142.141.36:10000
      writeDeadline: 15
  edged:
    cgroupDriver: cgroupfs
    cgroupRoot: ""
    cgroupsPerQOS: true
    clusterDNS: 169.254.96.16
    clusterDomain: cluster.local
    devicePluginEnabled: false
    dockerAddress: unix:///var/run/docker.sock
    enable: true
    gpuPluginEnabled: false
    hostnameOverride: gandroid
    customInterfaceName: wlan0
    podSandboxImage: kubeedge/pause:3.1
    remoteImageEndpoint: unix:///var/run/dockershim.sock
    remoteRuntimeEndpoint: unix:///var/run/dockershim.sock
    runtimeType: docker
  eventBus:
    enable: false
    mqttMode: 2
    mqttQOS: 0
    mqttRetain: false
    mqttServerExternal: tcp://127.0.0.1:1883
    mqttServerInternal: tcp://127.0.0.1:1884
  metaManager:
    metaServer:
      enable: true    
```



## 常见问题

1. ### docker run hello-world失败

```Bash
kona:/ # docker run hello-world
docker run hello-world
Unable to find image 'hello-world:latest' locally
docker: Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io on [::1]:53: read udp [::1]:60174->[::1]:53: read: connection refused.
```

原因：

a. 没有hello-world镜像
b. 地址解析问题，无法获取到镜像，没有镜像docker无法运行容器

解决方法：

a. 需要改动/etc/resolv.conf文件，添加nameserver [114.114.114.114](http://114.114.114.114/)
b. adb pull hello-world 获取镜像
c. 重新运行docker run hello-world
