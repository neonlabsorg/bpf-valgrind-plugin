use solana_bpf_tracer_plugin_interface::bpf_tracer_plugin_interface::BpfTracerPlugin;

use crate::plugin::BpfValgrindPlugin;

mod config;
mod plugin;
mod worker;

#[no_mangle]
#[allow(improper_ctypes_definitions)]
/// # Safety
///
/// This function returns the SampleBpfTracerPlugin pointer as trait BpfTracerPlugin.
pub unsafe extern "C" fn _create_bpf_tracer_plugin() -> *mut dyn BpfTracerPlugin {
    Box::into_raw(Box::new(BpfValgrindPlugin::default()))
}
