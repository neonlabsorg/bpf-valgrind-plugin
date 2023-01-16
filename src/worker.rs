use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use bpf_profile::bpf::{Instruction, InstructionData};
use bpf_profile::gen::trace::Profile;
use log::error;
use solana_bpf_tracer_plugin_interface::bpf_tracer_plugin_interface::ExecutorAdditional;
use solana_rbpf::ebpf;
use solana_rbpf::ebpf::INSN_SIZE;
use solana_rbpf::static_analysis::{Analysis, TraceLogEntry};
use solana_sdk::pubkey::Pubkey;
use threadpool::ThreadPool;

use crate::config::PluginConfig;

#[derive(Debug)]
pub struct Worker {
    thread_pool: Mutex<ThreadPool>,
    config: Arc<PluginConfig>,
}

impl Worker {
    pub fn new(config: PluginConfig) -> Self {
        Self {
            thread_pool: Mutex::new(ThreadPool::new(config.num_threads())),
            config: Arc::new(config),
        }
    }

    pub fn wait_for_finishing(&self) {
        self.thread_pool.lock().expect("Poisoned Mutex").join()
    }

    pub fn process_trace(
        &self,
        program_id: &Pubkey,
        transaction_id: &[u8],
        trace: &[TraceLogEntry],
        executor: Arc<dyn ExecutorAdditional>,
    ) {
        if let Some(program_ids) = self.config.programs() {
            if !program_ids.is_empty() && !program_ids.contains(program_id) {
                return;
            }
        }

        let config = Arc::clone(&self.config);
        let program_id = *program_id;
        let transaction_id = solana_sdk::bs58::encode(transaction_id).into_string();
        let trace = trace.to_vec();
        self.thread_pool
            .lock()
            .expect("Poisoned Mutex")
            .execute(move || {
                if let Err(err) =
                    Self::write_profile(&config, &program_id, &transaction_id, executor, &trace)
                {
                    error!(
                        "Error writing profile for program ID = {} and transaction ID = {}: {:?}",
                        program_id, transaction_id, err,
                    );
                }
            });
    }

    fn write_profile(
        config: &PluginConfig,
        program_id: &Pubkey,
        transaction_id: &str,
        executor: Arc<dyn ExecutorAdditional>,
        trace: &[TraceLogEntry],
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

        let resolver = bpf_profile::resolver::read(dump_path.as_ref().and_then(|path| {
            if path.exists() {
                Some(path.as_ref())
            } else {
                None
            }
        }))?;

        let mut profile = Profile::new(resolver, asm_path.as_ref().map(|path| path.as_ref()))?;

        let analysis = executor
            .do_static_analysis()
            .map_err(|err| anyhow!("{err}"))?;
        let pc_to_insn_index = Self::calc_pc_to_insn_index(&analysis);

        let text_section_offset = executor.get_text_section_offset();
        let pc_offset = text_section_offset as usize / INSN_SIZE;

        let mut lc = -1;
        let instruction_iterator = trace.iter().map(|item| {
            Self::resolve_instruction(
                item,
                &executor,
                &analysis,
                &pc_to_insn_index,
                pc_offset,
                &mut lc,
            )
        });

        bpf_profile::gen::trace::process(instruction_iterator, &mut profile)?;

        profile.write_callgrind(BufWriter::new(File::create(output_path)?))?;

        Ok(())
    }

    fn resolve_instruction(
        item: &TraceLogEntry,
        executor: &Arc<dyn ExecutorAdditional>,
        analysis: &Analysis,
        pc_to_insn_index: &[usize],
        pc_offset: usize,
        lc: &mut isize,
    ) -> bpf_profile::error::Result<(usize, Instruction)> {
        let pc = item[11] as usize;
        let ebpf_instr = &analysis.instructions[pc_to_insn_index[pc]];
        let data = match ebpf_instr.opc {
            ebpf::EXIT => InstructionData::Exit,
            ebpf::CALL_IMM => {
                let mut target_pc = None;
                if executor.get_config().static_syscalls {
                    if ebpf_instr.src != 0 {
                        target_pc = Some(ebpf_instr.imm as usize);
                    }
                } else {
                    target_pc = executor.lookup_internal_function(ebpf_instr.imm as u32)
                }
                match target_pc {
                    Some(target_pc) => InstructionData::Call(INSN_SIZE * (target_pc + pc_offset)),
                    None => InstructionData::Other,
                }
            }
            ebpf::CALL_REG => {
                let registers = &item[0..11];
                assert!(ebpf_instr.imm >= 0);
                assert!((ebpf_instr.imm as usize) < registers.len());
                InstructionData::CallX(
                    registers[ebpf_instr.imm as usize] as usize + pc_offset * INSN_SIZE,
                )
            }
            _ => InstructionData::Other,
        };

        let text = executor.disassemble_instruction(ebpf_instr, &analysis.cfg_nodes);
        let instruction = Instruction::new(pc + pc_offset, data, text);

        *lc += 1;

        Ok((*lc as usize, instruction))
    }

    pub fn calc_pc_to_insn_index(analysis: &Analysis) -> Vec<usize> {
        let mut pc_to_insn_index = vec![
            0usize;
            analysis
                .instructions
                .last()
                .map(|insn| insn.ptr + 2)
                .unwrap_or(0)
        ];
        for (index, insn) in analysis.instructions.iter().enumerate() {
            pc_to_insn_index[insn.ptr] = index;
            pc_to_insn_index[insn.ptr + 1] = index;
        }
        pc_to_insn_index
    }
}
