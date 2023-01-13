use anyhow::anyhow;
use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;

use bpf_profile::bpf::{Instruction, InstructionData};
use bpf_profile::gen::trace::Profile;
use log::error;
use solana_bpf_tracer_plugin_interface::bpf_tracer_plugin_interface::ExecutableGetter;
use solana_rbpf::disassembler::disassemble_instruction;
use solana_rbpf::ebpf;
use solana_rbpf::ebpf::INSN_SIZE;
use solana_rbpf::elf::Executable;
use solana_rbpf::static_analysis::{Analysis, TraceLogEntry};
use solana_rbpf::vm::TestContextObject;
use solana_sdk::pubkey::Pubkey;

use crate::config::PluginConfig;

pub enum WorkerMessage {
    WriteProfile {
        program_id: Pubkey,
        transaction_id: String,
        trace: Vec<TraceLogEntry>,
        executable_getter: Arc<dyn ExecutableGetter>,
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
                    trace,
                    executable_getter,
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
                        executable_getter,
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
        executable_getter: &Arc<dyn ExecutableGetter>,
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

        let executable = executable_getter.get_executable();
        let analysis = Analysis::from_executable(executable).map_err(|err| anyhow!("{err}"))?;
        let pc_to_insn_index = Self::calc_pc_to_insn_index(&analysis);

        let text_section_offset =
            executable.get_text_bytes().0 - executable.get_ro_region().vm_addr;
        let pc_offset = text_section_offset as usize / INSN_SIZE;

        let mut lc = -1;
        let instruction_iterator = trace.iter().map(|item| {
            Self::resolve_instruction(
                item,
                executable_getter.get_executable(),
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
        executable: &Executable<TestContextObject>,
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
                if executable.get_loader().get_config().static_syscalls {
                    if ebpf_instr.src != 0 {
                        target_pc = Some(ebpf_instr.imm as usize);
                    }
                } else {
                    target_pc = executable.lookup_internal_function(ebpf_instr.imm as u32)
                }
                match target_pc {
                    Some(target_pc) => InstructionData::Call {
                        operation: "call".into(),
                        target: INSN_SIZE * (target_pc + pc_offset),
                    },
                    None => InstructionData::Other,
                }
            }
            ebpf::CALL_REG => {
                let registers = &item[0..11];
                assert!(ebpf_instr.imm >= 0);
                assert!((ebpf_instr.imm as usize) < registers.len());
                InstructionData::Call {
                    operation: "callx".into(),
                    target: registers[ebpf_instr.imm as usize] as usize + pc_offset * INSN_SIZE,
                }
            }
            _ => InstructionData::Other,
        };

        let text = disassemble_instruction(
            ebpf_instr,
            &analysis.cfg_nodes,
            executable.get_function_registry(),
            executable.get_loader(),
        );

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
