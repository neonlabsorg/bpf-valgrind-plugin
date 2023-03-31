use std::collections::BTreeSet;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::Error;
use serde::{Deserialize, Deserializer};
use solana_sdk::pubkey::{ParsePubkeyError, Pubkey};

const DEFAULT_NUM_THREADS: usize = 2;

#[derive(Debug, Deserialize)]
pub struct PluginConfig {
    output_dir: PathBuf,
    dump_dir: Option<PathBuf>,
    assembly_dir: Option<PathBuf>,
    #[serde(deserialize_with = "deserialize_programs")]
    programs: Option<BTreeSet<Pubkey>>,
    num_threads: Option<usize>,
}

impl PluginConfig {
    pub fn from_json(path: impl AsRef<Path>) -> anyhow::Result<Self> {
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

    pub fn num_threads(&self) -> usize {
        self.num_threads.unwrap_or(DEFAULT_NUM_THREADS)
    }
}

pub fn deserialize_programs<'de, D>(d: D) -> Result<Option<BTreeSet<Pubkey>>, D::Error>
where
    D: Deserializer<'de>,
{
    let programs: Option<Vec<String>> = serde::Deserialize::deserialize(d)?;
    let mut first_error: Option<ParsePubkeyError> = None;
    let programs: Option<BTreeSet<Pubkey>> = programs.map(|programs| {
        programs
            .iter()
            .filter_map(|pubkey| match Pubkey::from_str(pubkey) {
                Ok(pubkey) => Some(pubkey),
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                    None
                }
            })
            .collect()
    });
    match first_error {
        None => Ok(programs),
        Some(err) => Err(Error::custom(format!("{:?}", err))),
    }
}
