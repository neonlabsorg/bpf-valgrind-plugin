use std::sync::Arc;

use solana_bpf_tracer_plugin_interface::bpf_tracer_plugin_interface::{
    BpfTracerPlugin, BpfTracerPluginError, ExecutorAdditional, Result,
};
use solana_rbpf::static_analysis::TraceLogEntry;
use solana_sdk::{hash::Hash, pubkey::Pubkey};

use crate::config::PluginConfig;
use crate::worker::Worker;

#[derive(Debug, Default)]
pub struct BpfValgrindPlugin {
    worker: Option<Worker>,
}

impl BpfTracerPlugin for BpfValgrindPlugin {
    fn name(&self) -> &'static str {
        "Valgrind BPF profiling plugin"
    }

    fn on_load(&mut self, config_file: &str) -> Result<()> {
        let config = PluginConfig::from_json(config_file)
            .map_err(|err| BpfTracerPluginError::Custom(err.into()))?;
        self.worker = Some(Worker::new(config));

        Ok(())
    }

    fn on_unload(&mut self) {
        self.worker.take().map(|worker| worker.wait_for_finishing());
    }

    fn trace_bpf(
        &mut self,
        program_id: &Pubkey,
        _block_hash: &Hash,
        transaction_id: &[u8],
        trace: &[TraceLogEntry],
        executor: Arc<dyn ExecutorAdditional>,
    ) -> Result<()> {
        self.worker
            .as_ref()
            .map(|worker| worker.process_trace(program_id, transaction_id, trace, executor));

        Ok(())
    }
}
