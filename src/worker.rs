use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use std::sync::mpsc::Receiver;
use std::sync::Mutex;
use std::thread;
use std::thread::JoinHandle;

use bpf_profile::bpf::{Instruction, InstructionData};
use bpf_profile::gen::trace::Profile;
use log::error;
use solana_rbpf::disassembler::disassemble_instruction;
use solana_rbpf::ebpf;
use solana_rbpf::vm::{TraceAnalyzer, TraceItem};
use solana_sdk::pubkey::Pubkey;

use crate::config::PluginConfig;

pub enum WorkerMessage {
    WriteProfile {
        program_id: Pubkey,
        transaction_id: String,
        trace_analyzer: TraceAnalyzer<'static>,
        trace: Vec<TraceItem>,
    },

    Shutdown,
}

pub struct Worker;

impl Worker {
    pub fn spawn(config: PluginConfig, receiver: Receiver<WorkerMessage>) -> JoinHandle<()> {
        let receiver = Mutex::new(receiver);
        thread::spawn(move || Self::process_messages(config, receiver))
    }

    fn process_messages(config: PluginConfig, receiver: Mutex<Receiver<WorkerMessage>>) {
        let receiver = match receiver.lock() {
            Ok(receiver) => receiver,
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        };

        while let Ok(message) = &receiver.recv() {
            match message {
                WorkerMessage::WriteProfile {
                    program_id,
                    transaction_id,
                    trace_analyzer,
                    trace,
                } => {
                    if let Some(program_ids) = config.programs() {
                        if !program_ids.is_empty() && !program_ids.contains(program_id) {
                            continue;
                        }
                    }

                    if let Err(err) = Self::write_profile(
                        &config,
                        program_id,
                        transaction_id,
                        trace_analyzer,
                        trace,
                    ) {
                        error!(
                            "Error writing profile for program ID = {} and transaction ID = {}: {:?}",
                            program_id,
                            transaction_id,
                            err,
                        );
                    }
                }

                WorkerMessage::Shutdown => break,
            }
        }
    }

    fn write_profile(
        config: &PluginConfig,
        program_id: &Pubkey,
        transaction_id: &str,
        trace_analyzer: &TraceAnalyzer<'static>,
        trace: &[TraceItem],
    ) -> anyhow::Result<()> {
        let dump_path = config
            .dump_dir()
            .as_ref()
            .map(|dump_dir| dump_dir.join(format!("{}.dump", program_id)));

        let asm_path = config
            .assembly_dir()
            .as_ref()
            .map(|asm_dir| asm_dir.join(transaction_id))
            .map(|asm_dir| {
                create_dir_all(&asm_dir).map(|_| asm_dir.join(format!("{}.asm", program_id)))
            })
            .transpose()?;

        let output_dir = config.output_dir().join(transaction_id);
        create_dir_all(&output_dir)?;

        let output_path = output_dir.join(format!("{}.out", program_id));

        let resolver = bpf_profile::resolver::read(dump_path.as_ref().map(|path| path.as_ref()))?;
        let mut profile = Profile::new(resolver, asm_path.as_ref().map(|path| path.as_ref()))?;

        let mut lc = -1;
        let instruction_iterator = trace
            .iter()
            .map(|item| Self::resolve_instruction(item, trace_analyzer, &mut lc));

        bpf_profile::gen::trace::process(instruction_iterator, &mut profile)?;

        profile.write_callgrind(BufWriter::new(File::create(output_path)?))?;

        Ok(())
    }

    fn resolve_instruction(
        item: &TraceItem,
        trace_analyzer: &TraceAnalyzer,
        lc: &mut isize,
    ) -> bpf_profile::error::Result<(usize, Instruction)> {
        let ebpf_instr = trace_analyzer.instruction(item);
        let data = match ebpf_instr.opc {
            ebpf::EXIT => InstructionData::Exit,
            ebpf::CALL_IMM
                if !trace_analyzer
                    .syscall_symbols()
                    .contains_key(&(ebpf_instr.imm as u32)) =>
            {
                InstructionData::Call {
                    operation: "call".into(),
                    target: ebpf_instr.imm as usize,
                }
            }
            ebpf::CALL_REG => {
                let registers = TraceAnalyzer::registers(item);
                assert!(ebpf_instr.imm >= 0);
                assert!((ebpf_instr.imm as usize) < registers.len());
                InstructionData::Call {
                    operation: "callx".into(),
                    target: registers[ebpf_instr.imm as usize] as usize,
                }
            }
            _ => InstructionData::Other,
        };

        let text = disassemble_instruction(
            ebpf_instr,
            trace_analyzer.cfg_nodes(),
            trace_analyzer.syscall_symbols(),
            trace_analyzer.function_registry(),
        );

        let instruction = Instruction::new(TraceAnalyzer::pc(item), data, text);

        *lc += 1;

        Ok((*lc as usize, instruction))
    }
}
