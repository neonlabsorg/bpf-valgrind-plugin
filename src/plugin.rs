use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread::JoinHandle;

use log::error;
use solana_bpf_tracer_plugin_interface::bpf_tracer_plugin_interface::{
    BpfTracerPlugin, BpfTracerPluginError, Result,
};
use solana_rbpf::vm::{TraceAnalyzer, TraceItem};
use solana_sdk::{hash::Hash, pubkey::Pubkey};

use crate::config::PluginConfig;
use crate::worker::{Worker, WorkerMessage};

#[derive(Debug)]
struct WorkerStuff {
    sender: SyncSender<WorkerMessage>,
    worker_handle: JoinHandle<Result<()>>,
}

#[derive(Debug, Default)]
pub struct BpfValgrindPlugin {
    worker_stuff: Option<WorkerStuff>,
}

impl BpfTracerPlugin for BpfValgrindPlugin {
    fn name(&self) -> &'static str {
        "Valgrind BPF profiling plugin"
    }

    fn on_load(&mut self, config_file: &str) -> Result<()> {
        let config = PluginConfig::from_json(config_file)
            .map_err(|err| BpfTracerPluginError::Custom(err.into()))?;
        let (sender, receiver) = sync_channel(256);
        let worker_handle = Worker::spawn(config, receiver);
        self.worker_stuff = Some(WorkerStuff {
            sender,
            worker_handle,
        });

        Ok(())
    }

    fn on_unload(&mut self) {
        if let Some(worker_stuff) = self.worker_stuff.take() {
            let err = match worker_stuff.sender.send(WorkerMessage::Shutdown) {
                Err(err) => Box::new(err),
                Ok(()) => match worker_stuff.worker_handle.join() {
                    Err(err) => err,
                    Ok(Err(err)) => Box::new(err),
                    Ok(Ok(())) => return,
                },
            };
            error!("Error during unloading of {}: {:?}", self.name(), err);
        }
    }

    fn trace_bpf<'a>(
        &mut self,
        program_id: &Pubkey,
        _block_hash: &Hash,
        transaction_id: &[u8],
        trace_analyzer: &TraceAnalyzer,
        trace: &[TraceItem],
    ) -> Result<()> {
        if let Some(worker_stuff) = &self.worker_stuff {
            let worker_message = WorkerMessage::WriteProfile {
                program_id: *program_id,
                transaction_id: solana_sdk::bs58::encode(transaction_id).into_string(),
                trace_analyzer: trace_analyzer.to_owned(),
                trace: trace.to_owned(),
            };

            worker_stuff
                .sender
                .send(worker_message)
                .map_err(|err| BpfTracerPluginError::Custom(err.into()))?;
        }

        Ok(())
    }
}
