use std::collections::BTreeSet;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug, Deserialize)]
pub struct PluginConfig {
    output_dir: PathBuf,
    dump_dir: Option<PathBuf>,
    assembly_dir: Option<PathBuf>,
    programs: Option<BTreeSet<Pubkey>>,
}

impl PluginConfig {
    pub fn from_json(path: impl AsRef<Path>) -> Result<Self> {
        Ok(serde_json::from_str(&read_to_string(path)?)?)
    }

    pub fn output_dir(&self) -> &PathBuf {
        &self.output_dir
    }

    pub fn dump_dir(&self) -> &Option<PathBuf> {
        &self.dump_dir
    }

    pub fn assembly_dir(&self) -> &Option<PathBuf> {
        &self.assembly_dir
    }

    pub fn programs(&self) -> &Option<BTreeSet<Pubkey>> {
        &self.programs
    }
}
