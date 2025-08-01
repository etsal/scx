// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod domain;
use domain::DomainGroup;

pub mod tuner;
use tuner::Tuner;

pub mod load_balance;
use load_balance::LoadBalancer;

mod stats;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use stats::ClusterStats;
use stats::NodeStats;

use std::ffi::c_ulong;

#[macro_use]
extern crate static_assertions;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::info;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Core;
use scx_utils::Cpumask;
use scx_utils::Llc;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;

const MAX_DOMS: usize = bpf_intf::consts_MAX_DOMS as usize;
const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;

// Number of u64 words in a BPF CPU mask.
static mut MASK_LEN: usize = 0;

/// scx_wd40: A fork of the scx_rusty multi-domain scheduler.
///
/// The message below is from the original scx_rusty codebase:
///
/// The BPF part does simple vtime or round robin scheduling in each domain
/// while tracking average load of each domain and duty cycle of each task.
///
/// The userspace part performs two roles. First, it makes higher frequency
/// (100ms) tuning decisions. It identifies CPUs which are not too heavily
/// loaded and marks them so that they can pull tasks from other overloaded
/// domains on the fly.
///
/// Second, it drives lower frequency (2s) load balancing. It determines
/// whether load balancing is necessary by comparing domain load averages.
/// If there are large enough load differences, it examines upto 1024
/// recently active tasks on the domain to determine which should be
/// migrated.
///
/// The overhead of userspace operations is low. Load balancing is not
/// performed frequently, but work-conservation is still maintained through
/// tuning and greedy execution. Load balancing itself is not that expensive
/// either. It only accesses per-domain load metrics to determine the domains
/// that need load balancing, as well as limited number of per-task metrics
/// for each pushing domain.
///
/// An earlier variant of this scheduler was used to balance across six
/// domains, each representing a chiplet in a six-chiplet AMD processor, and
/// could match the performance of production setup using CFS.
///
/// WARNING: scx_rusty currently assumes that all domains have equal
/// processing power and at similar distances from each other. This
/// limitation will be removed in the future.
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration for under-utilized hosts, in microseconds.
    #[clap(short = 'u', long, default_value = "20000")]
    slice_us_underutil: u64,

    /// Scheduling slice duration for over-utilized hosts, in microseconds.
    #[clap(short = 'o', long, default_value = "1000")]
    slice_us_overutil: u64,

    /// Load balance interval in seconds.
    #[clap(short = 'i', long, default_value = "2.0")]
    interval: f64,

    /// The tuner runs at a higher frequency than the load balancer to dynamically
    /// tune scheduling behavior. Tuning interval in seconds.
    #[clap(short = 'I', long, default_value = "0.1")]
    tune_interval: f64,

    /// The half-life of task and domain load running averages in seconds.
    #[clap(short = 'l', long, default_value = "1.0")]
    load_half_life: f64,

    /// Build domains according to how CPUs are grouped at this cache level
    /// as determined by /sys/devices/system/cpu/cpuX/cache/indexI/id.
    #[clap(short = 'c', long, default_value = "3")]
    cache_level: u32,

    /// When non-zero, enable greedy task stealing. When a domain is idle, a cpu
    /// will attempt to steal tasks from another domain as follows:
    ///
    /// 1. Try to consume a task from the current domain
    /// 2. Try to consume a task from another domain in the current NUMA node
    ///    (or globally, if running on a single-socket system), if the domain
    ///    has at least this specified number of tasks enqueued.
    ///
    /// See greedy_threshold_x_numa to enable task stealing across NUMA nodes.
    /// Tasks stolen in this manner are not permanently stolen from their
    /// domain.
    #[clap(short = 'g', long, default_value = "1")]
    greedy_threshold: u32,

    /// When non-zero, enable greedy task stealing across NUMA nodes. The order
    /// of greedy task stealing follows greedy-threshold as described above, and
    /// greedy-threshold must be nonzero to enable task stealing across NUMA
    /// nodes.
    #[clap(long, default_value = "0")]
    greedy_threshold_x_numa: u32,

    /// Disable load balancing. Unless disabled, userspace will periodically calculate
    /// the load factor of each domain and instruct BPF which processes to move.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_load_balance: bool,

    /// Put per-cpu kthreads directly into local dsq's.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    kthreads_local: bool,

    /// In recent kernels (>=v6.6), the kernel is responsible for balancing
    /// kworkers across L3 cache domains. Exclude them from load-balancing
    /// to avoid conflicting operations. Greedy executions still apply.
    #[clap(short = 'b', long, action = clap::ArgAction::SetTrue)]
    balanced_kworkers: bool,

    /// Use FIFO scheduling instead of weighted vtime scheduling.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    fifo_sched: bool,

    /// Idle CPUs with utilization lower than this will get remote tasks
    /// directly pushed onto them. 0 disables, 100 always enables.
    #[clap(short = 'D', long, default_value = "90.0")]
    direct_greedy_under: f64,

    /// Idle CPUs with utilization lower than this may get kicked to
    /// accelerate stealing when a task is queued on a saturated remote
    /// domain. 0 disables, 100 enables always.
    #[clap(short = 'K', long, default_value = "100.0")]
    kick_greedy_under: f64,

    /// Whether tasks can be pushed directly to idle CPUs on NUMA nodes
    /// different than their domain's node. If direct-greedy-under is disabled,
    /// this option is a no-op. Otherwise, if this option is set to false
    /// (default), tasks will only be directly pushed to idle CPUs if they
    /// reside on the same NUMA node as the task's domain.
    #[clap(short = 'r', long, action = clap::ArgAction::SetTrue)]
    direct_greedy_numa: bool,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Enables soft NUMA affinity for tasks that use set_mempolicy. This
    /// may improve performance in some scenarios when using mempolicies.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    mempolicy_affinity: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. The scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Print version and exit.
    #[clap(long)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Tunable for prioritizing CPU performance by configuring the CPU frequency governor.
    /// Valid values are [0, 1024]. Higher values prioritize performance, lower values
    /// prioritize energy efficiency. When in doubt, use 0 or 1024.
    #[clap(long, default_value = "0")]
    perf: u32,
}

fn read_cpu_busy_and_total(reader: &procfs::ProcReader) -> Result<(u64, u64)> {
    let cs = reader
        .read_stat()
        .context("Failed to read procfs")?
        .total_cpu
        .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))?;

    Ok(match cs {
        procfs::CpuStat {
            user_usec: Some(user),
            nice_usec: Some(nice),
            system_usec: Some(system),
            idle_usec: Some(idle),
            iowait_usec: Some(iowait),
            irq_usec: Some(irq),
            softirq_usec: Some(softirq),
            stolen_usec: Some(stolen),
            guest_usec: _,
            guest_nice_usec: _,
        } => {
            let busy = user + system + nice + irq + softirq + stolen;
            let total = busy + idle + iowait;
            (busy, total)
        }
        _ => bail!("Some procfs stats are not populated!"),
    })
}

pub fn sub_or_zero(curr: &u64, prev: &u64) -> u64 {
    curr.checked_sub(*prev).unwrap_or(0u64)
}

pub fn update_bpf_mask(bpfptr: *mut types::scx_bitmap, cpumask: &Cpumask) -> Result<()> {
    let bpfmask = unsafe { &mut *bpfptr };

    unsafe { cpumask.write_to_ptr(&raw mut bpfmask.bits as *mut u64, MASK_LEN)? };

    Ok(())
}

#[derive(Clone, Debug)]
struct StatsCtx {
    cpu_busy: u64,
    cpu_total: u64,
    bpf_stats: Vec<u64>,
    time_used: Duration,
}

impl StatsCtx {
    fn read_bpf_stats(skel: &BpfSkel) -> Result<Vec<u64>> {
        let stats_map = &skel.maps.stats;
        let mut stats: Vec<u64> = Vec::new();

        for stat in 0..bpf_intf::stat_idx_RUSTY_NR_STATS {
            let cpu_stat_vec = stats_map
                .lookup_percpu(&stat.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to lookup stat {}", stat))?
                .expect("per-cpu stat should exist");
            let sum = cpu_stat_vec
                .iter()
                .map(|val| {
                    u64::from_ne_bytes(
                        val.as_slice()
                            .try_into()
                            .expect("Invalid value length in stat map"),
                    )
                })
                .sum();
            stats.push(sum);
        }
        Ok(stats)
    }

    fn blank() -> Self {
        Self {
            cpu_busy: 0,
            cpu_total: 0,
            bpf_stats: vec![0u64; bpf_intf::stat_idx_RUSTY_NR_STATS as usize],
            time_used: Duration::default(),
        }
    }

    fn new(skel: &BpfSkel, proc_reader: &procfs::ProcReader, time_used: Duration) -> Result<Self> {
        let (cpu_busy, cpu_total) = read_cpu_busy_and_total(proc_reader)?;

        Ok(Self {
            cpu_busy,
            cpu_total,
            bpf_stats: Self::read_bpf_stats(skel)?,
            time_used,
        })
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            cpu_busy: sub_or_zero(&self.cpu_busy, &rhs.cpu_busy),
            cpu_total: sub_or_zero(&self.cpu_total, &rhs.cpu_total),
            bpf_stats: self
                .bpf_stats
                .iter()
                .zip(rhs.bpf_stats.iter())
                .map(|(lhs, rhs)| sub_or_zero(&lhs, &rhs))
                .collect(),
            time_used: self.time_used - rhs.time_used,
        }
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,

    sched_interval: Duration,
    tune_interval: Duration,
    balance_load: bool,
    balanced_kworkers: bool,

    dom_group: Arc<DomainGroup>,

    proc_reader: procfs::ProcReader,

    lb_at: SystemTime,
    lb_stats: BTreeMap<usize, NodeStats>,
    time_used: Duration,

    tuner: Tuner,
    stats_server: StatsServer<StatsCtx, (StatsCtx, ClusterStats)>,
}

impl<'a> Scheduler<'a> {
    fn setup_allocators(skel: &mut BpfSkel<'a>) -> Result<()> {
        // Allocate the arena memory from the BPF side so userspace initializes it before starting
        // the scheduler. Despite the function call's name this is neither a test nor a test run,
        // it's the recommended way of executing SEC("syscall") probes.
        let mut args = types::arena_init_args {
            static_pages: bpf_intf::consts_STATIC_ALLOC_PAGES_GRANULARITY as c_ulong,
            task_ctx_size: std::mem::size_of::<types::task_ctx>() as c_ulong,
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let output = skel.progs.arena_init.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, p2dq_setup returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_topology_node(
        skel: &mut BpfSkel<'a>,
        mask: &[u64],
        data_size: usize,
        id: usize,
    ) -> Result<()> {
        let mut args = types::arena_alloc_mask_args {
            bitmap: 0 as c_ulong,
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };

        let output = skel.progs.arena_alloc_mask.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, setup_topology_node returned {}",
                output.return_value as i32
            );
        }

        let ptr = unsafe { std::mem::transmute::<u64, &mut [u64; 10]>(args.bitmap) };

        let (valid_mask, _) = ptr.split_at_mut(mask.len());
        valid_mask.clone_from_slice(mask);

        let mut args = types::arena_topology_node_init_args {
            bitmap: args.bitmap as c_ulong,
            data_size: data_size as c_ulong,
            id: id as c_ulong,
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let output = skel.progs.arena_topology_node_init.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "p2dq_topology_node_init returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_topology(skel: &mut BpfSkel<'a>) -> Result<()> {
        let topo = Topology::new().expect("Failed to build host topology");

        // We never use the topology-provided IDs, because we do not need them anymore now that
        // we have a proper topology struct. We instead only use sequential IDs we create
        // ourselves to attach to the topology nodes. This is because the Topology-provided IDs
        // are used to determine relations between topology nodes, e.g., LLCs belonging to a
        // node, while sequential IDs are useful for linearly scanning the topology, e.g.,
        // iterating over domains. This is why we LLC IDs and domain IDs in scx_wd40 are different.
        // For now we only need the sequential IDs, so use those. Eventually we will be able
        // to remove those, too, once we remove the hardcoded arrays from the code.
        Self::setup_topology_node(skel, topo.span.as_raw_slice(), 0, 0)?;

        for (id, (_, node)) in topo.nodes.into_iter().enumerate() {
            Self::setup_topology_node(skel, node.span.as_raw_slice(), 0, id)?;
        }

        for (id, (_, llc)) in topo.all_llcs.into_iter().into_iter().enumerate() {
            Self::setup_topology_node(
                skel,
                Arc::<Llc>::into_inner(llc)
                    .expect("missing llc")
                    .span
                    .as_raw_slice(),
                0,
                id,
            )?;
        }
        for (id, (_, core)) in topo.all_cores.into_iter().into_iter().enumerate() {
            Self::setup_topology_node(
                skel,
                Arc::<Core>::into_inner(core)
                    .expect("missing core")
                    .span
                    .as_raw_slice(),
                0,
                id,
            )?;
        }
        for (id, (_, cpu)) in topo.all_cpus.into_iter().into_iter().enumerate() {
            let mut mask = [0; 9];
            mask[cpu.id.checked_shr(64).unwrap_or(0)] |= 1 << (cpu.id % 64);
            Self::setup_topology_node(skel, &mask, 0, id)?;
        }

        Ok(())
    }

    fn setup_wd40(skel: &mut BpfSkel<'a>) -> Result<()> {
        // Allocate the arena memory from the BPF side so userspace initializes it before starting
        // the scheduler. Despite the function call's name this is neither a test nor a test run,
        // it's the recommended way of executing SEC("syscall") probes.
        let input = ProgramInput {
            ..Default::default()
        };
        let output = skel.progs.wd40_setup.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize WD40 arenas, wd40_arena_setup returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_arenas(skel: &mut BpfSkel<'a>) -> Result<()> {
        Self::setup_allocators(skel)?;
        Self::setup_topology(skel)?;
        Self::setup_wd40(skel)?;

        Ok(())
    }

    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        init_libbpf_logging(None);
        info!(
            "Running scx_wd40 (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let mut skel = scx_ops_open!(skel_builder, open_object, wd40).unwrap();

        // Initialize skel according to @opts.
        let domains = Arc::new(DomainGroup::new(&Topology::new()?)?);

        if *NR_CPU_IDS > MAX_CPUS {
            bail!(
                "Num possible CPU IDs ({}) exceeds maximum of ({})",
                *NR_CPU_IDS,
                MAX_CPUS
            );
        }

        if domains.nr_doms() > MAX_DOMS {
            bail!(
                "nr_doms ({}) is greater than MAX_DOMS ({})",
                domains.nr_doms(),
                MAX_DOMS
            );
        }

        skel.maps.bss_data.as_mut().unwrap().slice_ns = scx_enums.SCX_SLICE_DFL;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.nr_nodes = domains.nr_nodes() as u32;
        rodata.nr_doms = domains.nr_doms() as u32;
        rodata.nr_cpu_ids = *NR_CPU_IDS as u32;

        if opts.partial {
            skel.struct_ops.wd40_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
        skel.struct_ops.wd40_mut().exit_dump_len = opts.exit_dump_len;

        rodata.load_half_life = (opts.load_half_life * 1000000000.0) as u32;
        rodata.kthreads_local = opts.kthreads_local;
        rodata.fifo_sched = opts.fifo_sched;
        rodata.greedy_threshold = opts.greedy_threshold;
        rodata.greedy_threshold_x_numa = opts.greedy_threshold_x_numa;
        rodata.direct_greedy_numa = opts.direct_greedy_numa;
        rodata.mempolicy_affinity = opts.mempolicy_affinity;
        rodata.debug = opts.verbose as u32;
        rodata.wd40_perf_mode = opts.perf;

        let mut skel = scx_ops_load!(skel, wd40, uei)?;

        Self::setup_arenas(&mut skel)?;

        let bss_data = skel.maps.bss_data.as_mut().unwrap();
        info!(
            "Mask length {}, number of possible CPUs {}",
            bss_data.mask_size,
            skel.maps.rodata_data.as_mut().unwrap().nr_cpu_ids
        );
        // Read the mask length chosen by BPF. We count elements in the u64 array, like the BPF
        // program does.
        //
        // This invocation is safe because there is no concurrency in the program during initialization.
        unsafe { MASK_LEN = bss_data.mask_size as usize };

        let types::topo_level(index) = types::topo_level::TOPO_LLC;

        for numa in 0..domains.nr_nodes() {
            let mut numa_mask = Cpumask::new();
            let node_domains = domains.numa_doms(&numa);
            for dom in node_domains.iter() {
                let dom_mask = dom.mask();
                numa_mask = numa_mask.or(&dom_mask);
            }

            update_bpf_mask(bss_data.node_data[numa], &numa_mask)?;
            info!("NODE[{:02}] mask= {}", numa, numa_mask);

            for dom in node_domains.iter() {
                // XXX Remove this by using the topo node's cpumask.
                let ptr = bss_data.topo_nodes[index as usize][dom.id()];
                let domc = unsafe { std::mem::transmute::<u64, &mut types::dom_ctx>(ptr) };
                update_bpf_mask(domc.cpumask, &dom.mask())?;

                bss_data.dom_numa_id_map[dom.id()] =
                    numa.try_into().expect("NUMA ID could not fit into 32 bits");

                info!(" DOM[{:02}] mask= {}", dom.id(), dom.mask());
            }
        }

        // Actually get the scheduler starting.
        let struct_ops = Some(scx_ops_attach!(skel, wd40)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        for (id, dom) in domains.doms().iter() {
            let mut ctx = dom.ctx.lock().unwrap();

            let ptr = skel.maps.bss_data.as_mut().unwrap().topo_nodes[index as usize][*id];
            let domc = unsafe { std::mem::transmute::<u64, &mut types::dom_ctx>(ptr) };
            *ctx = Some(domc);
        }

        info!("WD40 scheduler started! Run `scx_wd40 --monitor` for metrics.");

        // Other stuff.
        let proc_reader = procfs::ProcReader::new();

        Ok(Self {
            skel,
            struct_ops, // should be held to keep it attached

            sched_interval: Duration::from_secs_f64(opts.interval),
            tune_interval: Duration::from_secs_f64(opts.tune_interval),
            balance_load: !opts.no_load_balance,
            balanced_kworkers: opts.balanced_kworkers,

            dom_group: domains.clone(),
            proc_reader,

            lb_at: SystemTime::now(),
            lb_stats: BTreeMap::new(),
            time_used: Duration::default(),

            tuner: Tuner::new(
                domains,
                opts.direct_greedy_under,
                opts.kick_greedy_under,
                opts.slice_us_underutil * 1000,
                opts.slice_us_overutil * 1000,
            )?,
            stats_server,
        })
    }

    fn cluster_stats(&self, sc: &StatsCtx, node_stats: BTreeMap<usize, NodeStats>) -> ClusterStats {
        let stat = |idx| sc.bpf_stats[idx as usize];
        let total = stat(bpf_intf::stat_idx_RUSTY_STAT_WAKE_SYNC)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_SYNC_PREV_IDLE)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_PREV_IDLE)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_IDLE)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_PINNED)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_DISPATCH)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY_FAR)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DSQ_DISPATCH)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_LOCAL)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_XNUMA);
        let stat_pct = |idx| stat(idx) as f64 / total as f64 * 100.0;

        let cpu_busy = if sc.cpu_total != 0 {
            (sc.cpu_busy as f64 / sc.cpu_total as f64) * 100.0
        } else {
            0.0
        };

        ClusterStats {
            at_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros()
                .try_into()
                .unwrap(),
            lb_at_us: self
                .lb_at
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros()
                .try_into()
                .unwrap(),
            total,
            slice_us: self.tuner.slice_ns / 1000,

            cpu_busy,
            load: node_stats.iter().map(|(_k, v)| v.load).sum::<f64>(),
            nr_migrations: sc.bpf_stats[bpf_intf::stat_idx_RUSTY_STAT_LOAD_BALANCE as usize],

            task_get_err: sc.bpf_stats[bpf_intf::stat_idx_RUSTY_STAT_TASK_GET_ERR as usize],
            time_used: sc.time_used.as_secs_f64(),

            sync_prev_idle: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_SYNC_PREV_IDLE),
            wake_sync: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_WAKE_SYNC),
            prev_idle: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_PREV_IDLE),
            greedy_idle: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_IDLE),
            pinned: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_PINNED),
            direct: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_DISPATCH),
            greedy: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY),
            greedy_far: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY_FAR),
            dsq_dispatch: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DSQ_DISPATCH),
            greedy_local: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_LOCAL),
            greedy_xnuma: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_XNUMA),
            kick_greedy: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_KICK_GREEDY),
            repatriate: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_REPATRIATE),
            dl_clamp: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DL_CLAMP),
            dl_preset: stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DL_PRESET),

            direct_greedy_cpus: self.tuner.direct_greedy_mask.as_raw_slice().to_owned(),
            kick_greedy_cpus: self.tuner.kick_greedy_mask.as_raw_slice().to_owned(),

            nodes: node_stats,
        }
    }

    fn lb_step(&mut self) -> Result<()> {
        let mut lb = LoadBalancer::new(
            &mut self.skel,
            self.dom_group.clone(),
            self.balanced_kworkers,
            self.tuner.fully_utilized,
            self.balance_load,
        );

        lb.load_balance()?;

        self.lb_at = SystemTime::now();
        self.lb_stats = lb.get_stats();
        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let now = Instant::now();
        let mut next_tune_at = now + self.tune_interval;
        let mut next_sched_at = now + self.sched_interval;

        self.skel.maps.stats.value_size() as usize;

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let now = Instant::now();

            if now >= next_tune_at {
                self.tuner.step(&mut self.skel)?;
                next_tune_at += self.tune_interval;
                if next_tune_at < now {
                    next_tune_at = now + self.tune_interval;
                }
            }

            if now >= next_sched_at {
                self.lb_step()?;
                next_sched_at += self.sched_interval;
                if next_sched_at < now {
                    next_sched_at = now + self.sched_interval;
                }
            }

            self.time_used += Instant::now().duration_since(now);

            match req_ch.recv_deadline(next_sched_at.min(next_tune_at)) {
                Ok(prev_sc) => {
                    let cur_sc = StatsCtx::new(&self.skel, &self.proc_reader, self.time_used)?;
                    let delta_sc = cur_sc.delta(&prev_sc);
                    let cstats = self.cluster_stats(&delta_sc, self.lb_stats.clone());
                    res_ch.send((cur_sc, cstats))?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "scx_wd40: {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            stats::monitor(Duration::from_secs_f64(intv), shutdown_copy).unwrap()
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
