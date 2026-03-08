pub mod anti_debug;
pub mod anti_sandbox;
pub mod anti_vm;
pub mod api_hash;
pub mod check;
pub mod errors;
pub mod inject;
pub mod obfuscate;
pub mod packer;
pub mod fileless;

pub use anti_debug::AntiDebug;
pub use anti_sandbox::AntiSandbox;
pub use anti_vm::{AntiVM, VMType};
pub use api_hash::{
    ApiResolver, djb2_hash, djb2_hash_lowercase, jenkins_hash, win_api_hashes,
};
pub use check::{EvasionCheckResult, EvasionConfig, EvasionTask};
pub use errors::EvasionError;
pub use fileless::{FilelessExecutor, ShellcodeRunner};
pub use inject::{
    ProcessGhosting, ProcessInjector, InjectionResult, ThreadHijacker,
    ReflectiveDllInjector,
};
pub use obfuscate::{
    ControlFlowObfuscator, DeadCodeInserter, InstructionReorderer, ObfuscationPipeline,
    StringObfuscator,
};
pub use packer::{Packer, PackedExecutable, Unpacker};
