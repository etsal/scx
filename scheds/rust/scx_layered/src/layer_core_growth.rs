use anyhow::Result;
use std::collections::BTreeMap;

use clap::Parser;
use scx_utils::Topology;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;

use crate::bpf_intf;
use crate::CpuPool;
use crate::LayerSpec;

#[derive(Clone, Debug, PartialEq, Parser, Serialize, Deserialize)]
#[clap(rename_all = "snake_case")]
pub enum LayerGrowthAlgo {
    /// Grab CPUs from NUMA nodes, iteratively, in reverse order.
    NodeSpreadReverse,
    /// Grab CPUs from NUMA nodes, iteratively, in random order.
    NodeSpreadRandom,
}

const GROWTH_ALGO_NODE_SPREAD_REVERSE: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_NODE_SPREAD_REVERSE as i32;
const GROWTH_ALGO_NODE_SPREAD_RANDOM: i32 =
    bpf_intf::layer_growth_algo_GROWTH_ALGO_NODE_SPREAD_RANDOM as i32;

impl LayerGrowthAlgo {
    pub fn as_bpf_enum(&self) -> i32 {
        match self {
            LayerGrowthAlgo::NodeSpreadReverse => GROWTH_ALGO_NODE_SPREAD_REVERSE,
            LayerGrowthAlgo::NodeSpreadRandom => GROWTH_ALGO_NODE_SPREAD_RANDOM,
        }
    }

    pub fn layer_core_orders(
        cpu_pool: &CpuPool,
        layer_specs: &[LayerSpec],
        topo: &Topology,
    ) -> Result<BTreeMap<usize, Vec<usize>>> {
        let mut core_orders = BTreeMap::new();

        for (idx, spec) in layer_specs.iter().enumerate() {
            let layer_growth_algo = spec.kind.common().growth_algo.clone();
            let core_order =
                layer_growth_algo.layer_core_order(cpu_pool, layer_specs, spec, idx, topo)?;

            let core_order = match &spec.cpuset {
                Some(mask) => core_order
                    .into_iter()
                    .filter(|cpu| mask.test_cpu(*cpu))
                    .collect(),
                None => core_order,
            };

            core_orders.insert(idx, core_order);
        }

        Ok(core_orders)
    }

    fn layer_core_order(
        &self,
        _cpu_pool: &CpuPool,
        layer_specs: &[LayerSpec],
        spec: &LayerSpec,
        layer_idx: usize,
        topo: &Topology,
    ) -> Result<Vec<usize>> {
        let generator = LayerCoreOrderGenerator {
            layer_specs,
            spec,
            layer_idx,
            topo,
        };
        Ok(match self {
            LayerGrowthAlgo::NodeSpreadReverse => generator.grow_node_spread_reverse(),
            LayerGrowthAlgo::NodeSpreadRandom => generator.grow_node_spread_random(),
        })
    }
}

impl Default for LayerGrowthAlgo {
    fn default() -> Self {
        LayerGrowthAlgo::NodeSpreadRandom
    }
}

struct LayerCoreOrderGenerator<'a> {
    layer_specs: &'a [LayerSpec],
    #[allow(dead_code)]
    spec: &'a LayerSpec,
    layer_idx: usize,
    topo: &'a Topology,
}

impl<'a> LayerCoreOrderGenerator<'a> {
    fn rotate_layer_offset(&self, vec: &'a mut Vec<usize>) -> &Vec<usize> {
        let num_cores = self.topo.all_cores.len();
        let chunk = num_cores.div_ceil(self.layer_specs.len());
        vec.rotate_right((chunk * self.layer_idx).min(num_cores));
        vec
    }

    fn grow_node_spread_inner(&self, make_random: bool) -> Vec<usize> {
        let mut cores: Vec<usize> = Vec::new();
        let mut node_core_vecs: Vec<Vec<usize>> = Vec::new();
        let mut max_node_cpus: usize = 0;

        for (node_id, node) in self.topo.nodes.iter() {
            let flat_node_vec: Vec<usize> = node
                .llcs
                .iter()
                .flat_map(|(llc_id, llc)| {
                    llc.cores
                        .iter()
                        .map(|(core_id, core)| {
                            // this debug information is important.
                            for (cpu_id, _) in core.cpus.iter() {
                                debug!(
                                    "NODE_ID: {} LLC_ID: {} CORE_ID: {} CPU_ID: {}",
                                    node_id, llc_id, core_id, cpu_id
                                );
                            }
                            core_id.clone()
                        })
                        .collect::<Vec<usize>>()
                })
                .collect();
            max_node_cpus = std::cmp::max(flat_node_vec.len(), max_node_cpus);
            node_core_vecs.push(flat_node_vec.clone());
        }

        if make_random {
            for mut core_vec in &mut node_core_vecs {
                fastrand::shuffle(&mut core_vec);
            }
        }

        for i in 0..=max_node_cpus {
            for sub_vec in node_core_vecs.iter() {
                if i < sub_vec.len() {
                    cores.push(sub_vec[i]);
                }
            }
        }
        self.rotate_layer_offset(&mut cores);
        cores
    }

    fn grow_node_spread_reverse(&self) -> Vec<usize> {
        let mut cores = self.grow_node_spread();
        cores.reverse();
        cores
    }

    fn grow_node_spread(&self) -> Vec<usize> {
        return self.grow_node_spread_inner(false);
    }

    fn grow_node_spread_random(&self) -> Vec<usize> {
        return self.grow_node_spread_inner(true);
    }
}
