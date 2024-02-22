// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use crate::{landlock, Landlock, LandlockError};
use net_util::MacAddr;
use serde::{Deserialize, Serialize};
use std::{
    cell::{RefCell, RefMut},
    net::Ipv4Addr,
    path::PathBuf,
    rc::Rc,
    result,
};
use virtio_devices::RateLimiterConfig;

pub type LandlockResult<T> = result::Result<T, LandlockError>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuAffinity {
    pub vcpu: u8,
    pub host_cpus: Vec<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuFeatures {
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub amx: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuTopology {
    pub threads_per_core: u8,
    pub cores_per_die: u8,
    pub dies_per_package: u8,
    pub packages: u8,
}

// When booting with PVH boot the maximum physical addressable size
// is a 46 bit address space even when the host supports with 5-level
// paging.
pub const DEFAULT_MAX_PHYS_BITS: u8 = 46;

pub fn default_cpuconfig_max_phys_bits() -> u8 {
    DEFAULT_MAX_PHYS_BITS
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpusConfig {
    pub boot_vcpus: u8,
    pub max_vcpus: u8,
    #[serde(default)]
    pub topology: Option<CpuTopology>,
    #[serde(default)]
    pub kvm_hyperv: bool,
    #[serde(default = "default_cpuconfig_max_phys_bits")]
    pub max_phys_bits: u8,
    #[serde(default)]
    pub affinity: Option<Vec<CpuAffinity>>,
    #[serde(default)]
    pub features: CpuFeatures,
}

pub const DEFAULT_VCPUS: u8 = 1;

impl Default for CpusConfig {
    fn default() -> Self {
        CpusConfig {
            boot_vcpus: DEFAULT_VCPUS,
            max_vcpus: DEFAULT_VCPUS,
            topology: None,
            kvm_hyperv: false,
            max_phys_bits: DEFAULT_MAX_PHYS_BITS,
            affinity: None,
            features: CpuFeatures::default(),
        }
    }
}

pub const DEFAULT_NUM_PCI_SEGMENTS: u16 = 1;
pub fn default_platformconfig_num_pci_segments() -> u16 {
    DEFAULT_NUM_PCI_SEGMENTS
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PlatformConfig {
    #[serde(default = "default_platformconfig_num_pci_segments")]
    pub num_pci_segments: u16,
    #[serde(default)]
    pub iommu_segments: Option<Vec<u16>>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub oem_strings: Option<Vec<String>>,
    #[cfg(feature = "tdx")]
    #[serde(default)]
    pub tdx: bool,
    #[cfg(feature = "sev_snp")]
    #[serde(default)]
    pub sev_snp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MemoryZoneConfig {
    pub id: String,
    pub size: u64,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub host_numa_node: Option<u32>,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
}
impl MemoryZoneConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let memory_zone_flags = landlock::READ | landlock::WRITE;
        if let Some(file) = self.file {
            landlock.add_rule_with_flags(file, memory_zone_flags)?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum HotplugMethod {
    #[default]
    Acpi,
    VirtioMem,
}

fn default_memoryconfig_thp() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MemoryConfig {
    pub size: u64,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub hotplug_method: HotplugMethod,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub zones: Option<Vec<MemoryZoneConfig>>,
    #[serde(default = "default_memoryconfig_thp")]
    pub thp: bool,
}

pub const DEFAULT_MEMORY_MB: u64 = 512;

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            size: DEFAULT_MEMORY_MB << 20,
            mergeable: false,
            hotplug_method: HotplugMethod::Acpi,
            hotplug_size: None,
            hotplugged_size: None,
            shared: false,
            hugepages: false,
            hugepage_size: None,
            prefault: false,
            zones: None,
            thp: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum VhostMode {
    #[default]
    Client,
    Server,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RateLimiterGroupConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub rate_limiter_config: RateLimiterConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VirtQueueAffinity {
    pub queue_index: u16,
    pub host_cpus: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DiskConfig {
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_diskconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_diskconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub rate_limit_group: Option<String>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default)]
    pub id: Option<String>,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_io_uring: bool,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_aio: bool,
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub queue_affinity: Option<Vec<VirtQueueAffinity>>,
}

impl DiskConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        // Allow Read and Write permissions to Disk Paths
        let disk_flags = landlock::READ | landlock::WRITE;
        if let Some(path) = self.path {
            landlock.add_rule_with_flags(path, disk_flags)?;
        }
        Ok(())
    }
}
pub const DEFAULT_DISK_NUM_QUEUES: usize = 1;

pub fn default_diskconfig_num_queues() -> usize {
    DEFAULT_DISK_NUM_QUEUES
}

pub const DEFAULT_DISK_QUEUE_SIZE: u16 = 128;

pub fn default_diskconfig_queue_size() -> u16 {
    DEFAULT_DISK_QUEUE_SIZE
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NetConfig {
    #[serde(default = "default_netconfig_tap")]
    pub tap: Option<String>,
    #[serde(default = "default_netconfig_ip")]
    pub ip: Ipv4Addr,
    #[serde(default = "default_netconfig_mask")]
    pub mask: Ipv4Addr,
    #[serde(default = "default_netconfig_mac")]
    pub mac: MacAddr,
    #[serde(default)]
    pub host_mac: Option<MacAddr>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_netconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_netconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub vhost_mode: VhostMode,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub fds: Option<Vec<i32>>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default = "default_netconfig_true")]
    pub offload_tso: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_ufo: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_csum: bool,
}

pub fn default_netconfig_true() -> bool {
    true
}

pub fn default_netconfig_tap() -> Option<String> {
    None
}

pub fn default_netconfig_ip() -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 249, 1)
}

pub fn default_netconfig_mask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}

pub fn default_netconfig_mac() -> MacAddr {
    MacAddr::local_random()
}

pub const DEFAULT_NET_NUM_QUEUES: usize = 2;

pub fn default_netconfig_num_queues() -> usize {
    DEFAULT_NET_NUM_QUEUES
}

pub const DEFAULT_NET_QUEUE_SIZE: u16 = 256;

pub fn default_netconfig_queue_size() -> u16 {
    DEFAULT_NET_QUEUE_SIZE
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RngConfig {
    pub src: PathBuf,
    #[serde(default)]
    pub iommu: bool,
}

pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";

impl Default for RngConfig {
    fn default() -> Self {
        RngConfig {
            src: PathBuf::from(DEFAULT_RNG_SOURCE),
            iommu: false,
        }
    }
}

impl RngConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        // Allow Read permissions to Rng Paths
        let rng_flags = landlock::READ;
        landlock.add_rule_with_flags(self.src, rng_flags)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BalloonConfig {
    pub size: u64,
    /// Option to deflate the balloon in case the guest is out of memory.
    #[serde(default)]
    pub deflate_on_oom: bool,
    /// Option to enable free page reporting from the guest.
    #[serde(default)]
    pub free_page_reporting: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FsConfig {
    pub tag: String,
    pub socket: PathBuf,
    #[serde(default = "default_fsconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_fsconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

pub fn default_fsconfig_num_queues() -> usize {
    1
}

pub fn default_fsconfig_queue_size() -> u16 {
    1024
}

impl FsConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let fs_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.socket, fs_flags)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PmemConfig {
    pub file: PathBuf,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub discard_writes: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

impl PmemConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        // Allow Read and Write permissions to Pmem Paths
        let pmem_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.file, pmem_flags)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ConsoleOutputMode {
    Off,
    Pty,
    Tty,
    File,
    Socket,
    Null,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConsoleConfig {
    #[serde(default = "default_consoleconfig_file")]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    #[serde(default)]
    pub iommu: bool,
    pub socket: Option<PathBuf>,
}

pub fn default_consoleconfig_file() -> Option<PathBuf> {
    None
}

impl ConsoleConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let console_flags = landlock::READ | landlock::WRITE;

        if let Some(file) = self.file {
            landlock.add_rule_with_flags(file, console_flags)?;
        }
        if let Some(socket) = self.socket {
            landlock.add_rule_with_flags(socket, console_flags)?;
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DebugConsoleConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    /// Optionally dedicated I/O-port, if the default port should not be used.
    pub iobase: Option<u16>,
}

#[cfg(target_arch = "x86_64")]
impl Default for DebugConsoleConfig {
    fn default() -> Self {
        Self {
            file: None,
            mode: ConsoleOutputMode::Off,
            iobase: Some(devices::debug_console::DEFAULT_PORT as u16),
        }
    }
}
#[cfg(target_arch = "x86_64")]
impl DebugConsoleConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let debug_console_flags = landlock::READ | landlock::WRITE;

        if let Some(file) = self.file {
            landlock.add_rule_with_flags(file, debug_console_flags)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default)]
    pub x_nv_gpudirect_clique: Option<u8>,
}

impl DeviceConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let device_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.path, device_flags)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct UserDeviceConfig {
    pub socket: PathBuf,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

impl UserDeviceConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let user_device_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.socket, user_device_flags)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VdpaConfig {
    pub path: PathBuf,
    #[serde(default = "default_vdpaconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

pub fn default_vdpaconfig_num_queues() -> usize {
    1
}

impl VdpaConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let vdpa_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.path, vdpa_flags)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VsockConfig {
    pub cid: u32,
    pub socket: PathBuf,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

impl VsockConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let vsock_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.socket, vsock_flags)?;
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SgxEpcConfig {
    pub id: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub prefault: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NumaDistance {
    #[serde(default)]
    pub destination: u32,
    #[serde(default)]
    pub distance: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NumaConfig {
    #[serde(default)]
    pub guest_numa_id: u32,
    #[serde(default)]
    pub cpus: Option<Vec<u8>>,
    #[serde(default)]
    pub distances: Option<Vec<NumaDistance>>,
    #[serde(default)]
    pub memory_zones: Option<Vec<String>>,
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub sgx_epc_sections: Option<Vec<String>>,
    #[serde(default)]
    pub pci_segments: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayloadConfig {
    #[serde(default)]
    pub firmware: Option<PathBuf>,
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    #[serde(default)]
    pub cmdline: Option<String>,
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
    #[cfg(feature = "igvm")]
    #[serde(default)]
    pub igvm: Option<PathBuf>,
    #[cfg(feature = "sev_snp")]
    #[serde(default)]
    pub host_data: Option<String>,
}

impl PayloadConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let payload_flags = landlock::READ;

        if let Some(firmware) = self.firmware.as_ref() {
            landlock.add_rule_with_flags(firmware.to_path_buf(), payload_flags)?;
        }

        if let Some(kernel) = self.kernel.as_ref() {
            landlock.add_rule_with_flags(kernel.to_path_buf(), payload_flags)?;
        }

        if let Some(initramfs) = self.initramfs.as_ref() {
            landlock.add_rule_with_flags(initramfs.to_path_buf(), payload_flags)?;
        }

        #[cfg(feature = "igvm")]
        if let Some(igvm) = self.igvm.as_ref() {
            landlock.add_rule_with_flags(igvm.to_path_buf(), payload_flags)?;
        }
        Ok(())
    }
}

pub fn default_serial() -> ConsoleConfig {
    ConsoleConfig {
        file: None,
        mode: ConsoleOutputMode::Null,
        iommu: false,
        socket: None,
    }
}

pub fn default_console() -> ConsoleConfig {
    ConsoleConfig {
        file: None,
        mode: ConsoleOutputMode::Tty,
        iommu: false,
        socket: None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct TpmConfig {
    pub socket: PathBuf,
}

impl TpmConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        let tpm_flags = landlock::READ | landlock::WRITE;
        landlock.add_rule_with_flags(self.socket, tpm_flags)?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LandlockConfig {
    pub path: PathBuf,
    pub flags: u8,
}

impl LandlockConfig {
    pub fn apply_landlock(self, mut landlock: RefMut<Landlock>) -> LandlockResult<()> {
        landlock.add_rule_with_flags(self.path, self.flags)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VmConfig {
    #[serde(default)]
    pub cpus: CpusConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    pub payload: Option<PayloadConfig>,
    pub rate_limit_groups: Option<Vec<RateLimiterGroupConfig>>,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    #[serde(default)]
    pub rng: RngConfig,
    pub balloon: Option<BalloonConfig>,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default = "default_serial")]
    pub serial: ConsoleConfig,
    #[serde(default = "default_console")]
    pub console: ConsoleConfig,
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub debug_console: DebugConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub user_devices: Option<Vec<UserDeviceConfig>>,
    pub vdpa: Option<Vec<VdpaConfig>>,
    pub vsock: Option<VsockConfig>,
    #[serde(default)]
    pub pvpanic: bool,
    #[serde(default)]
    pub iommu: bool,
    #[cfg(target_arch = "x86_64")]
    pub sgx_epc: Option<Vec<SgxEpcConfig>>,
    pub numa: Option<Vec<NumaConfig>>,
    #[serde(default)]
    pub watchdog: bool,
    #[cfg(feature = "guest_debug")]
    #[serde(default)]
    pub gdb: bool,
    pub platform: Option<PlatformConfig>,
    pub tpm: Option<TpmConfig>,
    // Preserved FDs are the ones that share the same life-time as its holding
    // VmConfig instance, such as FDs for creating TAP devices.
    // Preserved FDs will stay open as long as the holding VmConfig instance is
    // valid, and will be closed when the holding VmConfig instance is destroyed.
    #[serde(skip)]
    pub preserved_fds: Option<Vec<i32>>,
    pub landlock_enable: bool,
    pub landlock_config: Option<Vec<LandlockConfig>>,
}

impl VmConfig {
    pub fn apply_landlock(&self, landlock: Rc<RefCell<Landlock>>) -> LandlockResult<()> {
        if let Some(mem_zones) = self.memory.zones.as_ref() {
            for zone in mem_zones.iter() {
                zone.clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        let disks = self.disks.as_ref();
        if let Some(disks) = disks {
            for disk in disks.iter() {
                disk.clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        self.rng
            .clone()
            .apply_landlock(landlock.as_ref().borrow_mut())?;

        if let Some(fs_configs) = self.fs.as_ref() {
            for fs_config in fs_configs.iter() {
                fs_config
                    .clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        if let Some(pmem_configs) = self.pmem.as_ref() {
            for pmem_config in pmem_configs.iter() {
                pmem_config
                    .clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        self.console
            .clone()
            .apply_landlock(landlock.as_ref().borrow_mut())?;
        self.serial
            .clone()
            .apply_landlock(landlock.as_ref().borrow_mut())?;
        #[cfg(target_arch = "x86_64")]
        self.debug_console
            .clone()
            .apply_landlock(landlock.as_ref().borrow_mut())?;

        if let Some(devices) = self.devices.as_ref() {
            for device in devices.iter() {
                device
                    .clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        if let Some(user_devices) = self.user_devices.as_ref() {
            for user_devices in user_devices.iter() {
                user_devices
                    .clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        if let Some(vdpa_configs) = self.vdpa.as_ref() {
            for vdpa_config in vdpa_configs.iter() {
                vdpa_config
                    .clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        if let Some(vsock_config) = self.vsock.as_ref() {
            vsock_config
                .clone()
                .apply_landlock(landlock.as_ref().borrow_mut())?;
        }

        let payload = self.payload.as_ref();
        if let Some(payload) = payload {
            payload
                .clone()
                .apply_landlock(landlock.as_ref().borrow_mut())?;
        }

        if let Some(tpm_config) = self.tpm.as_ref() {
            tpm_config
                .clone()
                .apply_landlock(landlock.as_ref().borrow_mut())?;
        }

        if self.net.is_some() {
            let net_flags = landlock::READ | landlock::WRITE;
            landlock
                .borrow_mut()
                .add_rule_with_flags("/dev/net/tun".into(), net_flags)?;
        }

        if self.landlock_config.is_some() {
            for landlock_config in self.landlock_config.as_ref().unwrap() {
                landlock_config
                    .clone()
                    .apply_landlock(landlock.as_ref().borrow_mut())?;
            }
        }

        Ok(())
    }
}
