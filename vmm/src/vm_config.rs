// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use crate::{
    landlock::{self, LandlockError},
    Landlock,
};
use net_util::MacAddr;
use serde::{Deserialize, Serialize};
use std::{fs, net::Ipv4Addr, path::PathBuf, result};
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

pub const DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT: u32 = 1;

fn default_pci_segment_aperture_weight() -> u32 {
    DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PciSegmentConfig {
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default = "default_pci_segment_aperture_weight")]
    pub mmio32_aperture_weight: u32,
    #[serde(default = "default_pci_segment_aperture_weight")]
    pub mmio64_aperture_weight: u32,
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let memory_zone_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        if let Some(file) = &self.file {
            landlock.add_rule_with_perms(file.to_path_buf(), memory_zone_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let disk_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        if let Some(path) = &self.path {
            landlock.add_rule_with_perms(path.to_path_buf(), disk_perms)?;
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
    #[serde(
        default,
        serialize_with = "serialize_netconfig_fds",
        deserialize_with = "deserialize_netconfig_fds"
    )]
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

fn serialize_netconfig_fds<S>(x: &Option<Vec<i32>>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(x) = x {
        warn!("'NetConfig' contains FDs that can't be serialized correctly. Serializing them as invalid FDs.");
        let invalid_fds = vec![-1; x.len()];
        s.serialize_some(&invalid_fds)
    } else {
        s.serialize_none()
    }
}

fn deserialize_netconfig_fds<'de, D>(d: D) -> Result<Option<Vec<i32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let invalid_fds: Option<Vec<i32>> = Option::deserialize(d)?;
    if let Some(invalid_fds) = invalid_fds {
        warn!("'NetConfig' contains FDs that can't be deserialized correctly. Deserializing them as invalid FDs.");
        Ok(Some(vec![-1; invalid_fds.len()]))
    } else {
        Ok(None)
    }
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        // Rng Path only need read perms
        let rng_perms = landlock::Perms::READ;
        landlock.add_rule_with_perms(self.src.to_path_buf(), rng_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let fs_flags = landlock::Perms::READ | landlock::Perms::WRITE;
        landlock.add_rule_with_perms(self.socket.to_path_buf(), fs_flags)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        // Allow Read and Write permissions to Pmem Paths
        let pmem_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        landlock.add_rule_with_perms(self.file.to_path_buf(), pmem_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let console_perms = landlock::Perms::READ | landlock::Perms::WRITE;

        if let Some(file) = &self.file {
            landlock.add_rule_with_perms(file.to_path_buf(), console_perms)?;
        }
        if let Some(socket) = &self.socket {
            landlock.add_rule_with_perms(socket.to_path_buf(), console_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let debug_console_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        if let Some(file) = &self.file {
            landlock.add_rule_with_perms(file.to_path_buf(), debug_console_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let device_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        let device_path = fs::read_link(self.path.as_path()).map_err(LandlockError::OpenPath)?;
        let iommu_group = device_path.file_name();
        let iommu_group_str = iommu_group
            .ok_or(LandlockError::InvalidPath)?
            .to_str()
            .ok_or(LandlockError::InvalidPath)?;

        let vfio_group_path = "/dev/vfio/".to_owned() + iommu_group_str;
        landlock.add_rule_with_perms(vfio_group_path.into(), device_perms)?;

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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let user_device_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        landlock.add_rule_with_perms(self.socket.to_path_buf(), user_device_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let vdpa_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        landlock.add_rule_with_perms(self.path.to_path_buf(), vdpa_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let vsock_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        landlock.add_rule_with_perms(self.socket.to_path_buf(), vsock_perms)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let payload_perms = landlock::Perms::READ;

        if let Some(firmware) = &self.firmware {
            landlock.add_rule_with_perms(firmware.to_path_buf(), payload_perms)?;
        }

        if let Some(kernel) = &self.kernel {
            landlock.add_rule_with_perms(kernel.to_path_buf(), payload_perms)?;
        }

        if let Some(initramfs) = &self.initramfs {
            landlock.add_rule_with_perms(initramfs.to_path_buf(), payload_perms)?;
        }

        #[cfg(feature = "igvm")]
        if let Some(igvm) = &self.igvm {
            landlock.add_rule_with_perms(igvm.to_path_buf(), payload_flags)?;
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
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        let tpm_perms = landlock::Perms::READ | landlock::Perms::WRITE;
        landlock.add_rule_with_perms(self.socket.to_path_buf(), tpm_perms)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LandlockConfig {
    pub path: PathBuf,
    #[serde(default = "default_landlock_perms")]
    pub perms: landlock::Perms,
}

pub fn default_landlock_perms() -> landlock::Perms {
    landlock::Perms::empty()
}

impl LandlockConfig {
    pub fn apply_landlock(&self, landlock: &mut Landlock) -> LandlockResult<()> {
        landlock.add_rule_with_perms(self.path.to_path_buf(), self.perms)?;
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
    pub pci_segments: Option<Vec<PciSegmentConfig>>,
    pub platform: Option<PlatformConfig>,
    pub tpm: Option<TpmConfig>,
    // Preserved FDs are the ones that share the same life-time as its holding
    // VmConfig instance, such as FDs for creating TAP devices.
    // Preserved FDs will stay open as long as the holding VmConfig instance is
    // valid, and will be closed when the holding VmConfig instance is destroyed.
    #[serde(skip)]
    pub preserved_fds: Option<Vec<i32>>,
    #[serde(default)]
    pub landlock_enable: bool,
    pub landlock_config: Option<Vec<LandlockConfig>>,
}

impl VmConfig {
    pub fn apply_landlock(&self) -> LandlockResult<()> {
        let mut landlock = Landlock::new()?;

        if let Some(mem_zones) = &self.memory.zones {
            for zone in mem_zones.iter() {
                zone.apply_landlock(&mut landlock)?;
            }
        }

        let disks = &self.disks;
        if let Some(disks) = disks {
            for disk in disks.iter() {
                disk.apply_landlock(&mut landlock)?;
            }
        }

        self.rng.apply_landlock(&mut landlock)?;

        if let Some(fs_configs) = &self.fs {
            for fs_config in fs_configs.iter() {
                fs_config.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(pmem_configs) = &self.pmem {
            for pmem_config in pmem_configs.iter() {
                pmem_config.apply_landlock(&mut landlock)?;
            }
        }

        self.console.apply_landlock(&mut landlock)?;
        self.serial.apply_landlock(&mut landlock)?;

        #[cfg(target_arch = "x86_64")]
        {
            self.debug_console.apply_landlock(&mut landlock)?;
        }

        if let Some(devices) = &self.devices {
            let vfio_dev_perms = landlock::Perms::READ | landlock::Perms::WRITE;
            landlock.add_rule_with_perms("/dev/vfio/vfio".into(), vfio_dev_perms)?;

            for device in devices.iter() {
                device.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(user_devices) = &self.user_devices {
            for user_devices in user_devices.iter() {
                user_devices.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(vdpa_configs) = &self.vdpa {
            for vdpa_config in vdpa_configs.iter() {
                vdpa_config.apply_landlock(&mut landlock)?;
            }
        }

        if let Some(vsock_config) = &self.vsock {
            vsock_config.apply_landlock(&mut landlock)?;
        }

        if let Some(payload) = &self.payload {
            payload.apply_landlock(&mut landlock)?;
        }

        if let Some(tpm_config) = &self.tpm {
            tpm_config.apply_landlock(&mut landlock)?;
        }

        if self.net.is_some() {
            let net_perms = landlock::Perms::READ | landlock::Perms::WRITE;
            landlock.add_rule_with_perms("/dev/net/tun".into(), net_perms)?;
        }

        if let Some(landlock_configs) = &self.landlock_config {
            for landlock_config in landlock_configs.iter() {
                landlock_config.apply_landlock(&mut landlock)?;
            }
        }

        landlock.restrict_self()?;

        Ok(())
    }
}
