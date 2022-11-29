# BPF Tracing Plugin for Profiling Solana Programs  
This plugin listens for BPF traces of programs execution on Solana validator 
and writes profile data in [Valgrind](https://valgrind.org) ([Callgrind](https://valgrind.org/docs/manual/cl-format.html)) data format.
It can be read by [callgrind_annotate](https://man7.org/linux/man-pages/man1/callgrind_annotate.1.html) and 
[KCachegrind (or QCacheGrind for Windows)](https://apps.kde.org/en/kcachegrind/).

## Usage

---
**Note:** As for 29.11.2022, Solana validator in the official repository doesn't support for this kind of plugins. 
You need to build validator from this repository/branch: https://github.com/neonlabsorg/solana/tree/bpf-tracing-plugins
---

### 0. Build Solana Validator
Build Solana validator with BPF Plugins support (from here: https://github.com/neonlabsorg/solana/tree/bpf-tracing-plugins)

### 1. Build Plugin
```shell
$ cargo build --release
```

### 2. Create Plugin Configuration
Create plugin configuration file (bpf-tracer-plugin.json):
```json
{
  "libpath": "/repo/bpf-valgrind-plugin/target/debug/libbpf_valgrind_plugin.so",
  "output_dir": "/opt/bpf-profiles",
  "assembly_dir": "/opt/bpf-profiles",
  "dump_dir": "/opt/dumps",
  "programs": ["6Zxwyt8bYzJwUotiNAB5x94vFML9jP5HiTMzpKXLcRYv"]
}
```

#### Where:
* `libpath` — path to plugin's binary
* `output_dir` — path where callgrind files will be stored. Files will be located under subdirectories, named by current 
   transactions ID in base58 encoding. Files will be named in the form: `<program_id>.out`, where `<program_id>` is 
   base58-encoded public key of the program.
* `assembly_dir` *[optional]* — path where asm files will be stored. Files will be located under subdirectories, named by current
  transactions ID in base58 encoding. Files will be named in the form: `<program_id>.asm`, where `<program_id>` is
  base58-encoded public key of the program. If this parameter is omitted, no assembly files will be written.
* `dump_dir` *[optional]* — path where to get dump files. You can create the dump file by passing `--dump` flag to `cargo-build-bpf`.
  These files must be named in the form: `<program_id>.dump`, where `<program_id>` is base58-encoded public key of the program.
* `programs` *[optional]* — list of base58-encoded public keys of programs being profiled. If omitted or empty, all executed 
  programs will be profiled.

### 3. Run Solana Local Cluster
1. Configure plugin path:
```shell
export SOLANA_RUN_SH_VALIDATOR_ARGS="--plugin-config bpf-tracer-plugin.json"
```
where `bpf-tracer-plugin.json` is the path to plugin's configuration file.

2. **[optional]** If you with to run **release** version of validator, you must also switch version using the environment variable:
```shell
export NDEBUG=true
```

3. Run Solana local cluster:
```shell
./scripts/run.sh
```

That's it! All profiles of executed programs (according to configuration) will be stored during this run.