# Sandboxing using Landlock LSM
Landlock is a lightweight mechanism to allow unprivileged applications to
sandbox themselves.

During initial stages of running, applications can define the set of resources
(mostly files) they need to access during their lifetime. All such rules are
used to create a ruleset. Once the ruleset is applied, the process cannot access
any resources outside of the ruleset during its lifetime, even if it were
comprimised.

## Host Setup
Landlock LSM should be enabled in Host kernel to use the feature with
cloud-hypervisor. Please following [Kernel-Support](https://docs.kernel.org/userspace-api/landlock.html#kernel-support) link to enable Landlock on Host kernel.


Landlock support can be checked with following command:
```
$ sudo dmesg | grep -w  landlock
[    0.000000] landlock: Up and running.
```
Linux kernel confirms Landlock LSM support with above message is dmesg.


## Implementation Details
Landlock is enabled in `vm_create` stage. As all the required guest configuration
(`struct VmConfig`) is available in `vm_create`, this stage is the earliest
place to enable Landlock.

## Enable Landlock
Append `--landlock` to Cloud-Hypervisor's command line to enable Landlock
support.

If you expect guest to access additional paths after it boots, for example hotplug,
those paths can be passed using `--landlock-rules` command line parameter.

## Examples
To enable Landlock:

```
./cloud-hypervisor \
	--kernel ./linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin \
	--disk path=focal-server-cloudimg-amd64.raw path=/tmp/ubuntu-cloudinit.img \
	--cmdline "console=hvc0 root=/dev/vda1 rw" \
	--cpus boot=4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
    --landlock
```
Hotplugging any new file-backed resources to above guest will result in
**Permission Denied** error.

To enable Landlock with hotplug support:
```
./cloud-hypervisor \
    --api-socket /tmpXXXX/ch.socket \
	--kernel ./linux-cloud-hypervisor/arch/x86/boot/compressed/vmlinux.bin \
	--disk path=focal-server-cloudimg-amd64.raw path=/tmp/ubuntu-cloudinit.img \
	--cmdline "console=hvc0 root=/dev/vda1 rw" \
	--cpus boot=4 \
	--memory size=1024M \
	--net "tap=,mac=,ip=,mask=" \
    --landlock \
    --landlock-rules path="/path/to/hotplug",flags="rw"

./ch-remote --api-socket /tmpXXXX/ch.socket \
    add-disk "path=/path/to/hotplug/blk.raw"
```
`/path/to/hotplug` in above example is a directory. Instead of the directory,
the path to the exact hotplugged disk image file can also be passed to
landlock-rules.


# References
* https://landlock.io/