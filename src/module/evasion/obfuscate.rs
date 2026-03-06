//! Code Obfuscation Module
//!
//! Provides various obfuscation techniques to evade detection:
//! - String encryption (XOR-based runtime encryption)
//! - Control flow obfuscation (opaque predicates, bogus control flow)
//! - Dead code insertion
//! - Instruction reordering

use rand::Rng;

/// String obfuscation using XOR encryption
pub struct StringObfuscator;

impl StringObfuscator {
    /// Encrypt a string at runtime
    /// Returns the encrypted bytes
    pub fn encrypt(s: &str) -> Vec<u8> {
        let key = Self::generate_key();
        Self::xor_encrypt(s.as_bytes(), &key)
    }

    /// Encrypt a string with a specific key
    pub fn encrypt_with_key(s: &str, key: &[u8]) -> Vec<u8> {
        Self::xor_encrypt(s.as_bytes(), key)
    }

    /// Decrypt an encrypted string
    pub fn decrypt(encrypted: &[u8], key: &[u8]) -> String {
        let decrypted = Self::xor_encrypt(encrypted, key); // XOR is symmetric
        String::from_utf8_lossy(&decrypted).to_string()
    }

    /// Generate a random encryption key
    pub fn generate_key() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let key_len = rng.gen_range(8..32);
        (0..key_len).map(|_| rng.gen::<u8>()).collect()
    }

    /// XOR encrypt/decrypt data
    fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .zip(key.iter().cycle())
            .map(|(&d, &k)| d ^ k)
            .collect()
    }
}

/// Control flow obfuscation
pub struct ControlFlowObfuscator;

impl ControlFlowObfuscator {
    /// Generate an opaque predicate that always evaluates to true
    /// but is difficult for static analysis to determine
    pub fn opaque_predicate_true() -> bool {
        // Based on properties that are hard for static analyzers
        // but always evaluate to true at runtime
        let x = 0x12345678u32;
        let y = x ^ 0xFFFFFFFF;
        let z = y ^ 0xFFFFFFFF;
        z == x
    }

    /// Generate an opaque predicate that always evaluates to false
    pub fn opaque_predicate_false() -> bool {
        !Self::opaque_predicate_true()
    }

    /// Execute a function with bogus control flow
    /// The bogus branches never execute but confuse analysis
    pub fn with_bogus_flow<T, F: FnOnce() -> T>(f: F) -> T {
        // Bogus control flow - these branches never taken
        let bogus = Self::generate_bogus_value();
        if bogus > 1000000 {
            // Dead code - never executed
            panic!("This should never happen");
        }

        // Real code
        let result = f();

        // More bogus flow
        if Self::opaque_predicate_false() {
            // Dead code
            std::process::exit(1);
        }

        result
    }

    /// Generate a bogus value for control flow
    fn generate_bogus_value() -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..100) // Always < 1000000
    }

    /// Flatten control flow using a state machine
    /// Makes the code harder to follow and analyze
    pub fn flattened_execution<F: FnMut(u32) -> Option<u32>>(mut f: F) {
        let mut state: u32 = 0;

        while state != 99 {
            state = match f(state) {
                Some(next) => next,
                None => 99,
            };
        }
    }
}

/// Dead code inserter
pub struct DeadCodeInserter;

impl DeadCodeInserter {
    /// Insert dead code that never executes but confuses analysis
    #[inline(always)]
    pub fn insert_dead_code() {
        if StringObfuscator::encrypt("").len() > 1000000 {
            // Dead code - condition never true
            let _x = 42;
            let _y = _x * 2;
        }
    }

    /// Generate a function with interleaved dead code
    pub fn with_dead_code<T, F: Fn() -> T>(f: F) -> T {
        Self::insert_dead_code();
        let result = f();
        Self::insert_dead_code();
        result
    }
}

/// Runtime string decryption macro helper
/// Usage: obfuscated_string!("secret_string")
#[macro_export]
macro_rules! obfuscated_string {
    ($s:literal) => {{
        const ENCRYPTED: &[u8] = &[];
        const KEY: &[u8] = &[];
        // In a real implementation, these would be compile-time generated
        // For now, this is a placeholder for the macro interface
        $s
    }};
}

/// Instruction reordering utility
pub struct InstructionReorderer;

impl InstructionReorderer {
    /// Reorder independent instructions while preserving semantics
    /// This is more of a conceptual implementation - real reordering
    /// would need to happen at compile time or via a custom compiler pass
    pub fn reorder_operations<T: Clone + std::ops::Add<Output = T>>(
        a: T,
        b: T,
        c: T,
    ) -> (T, T, T) {
        // Original: let x = a + b; let y = b + c; let z = a + c;
        // Reordered to confuse analysis

        let temp1 = a.clone() + b.clone(); // x
        let temp2 = b.clone() + c.clone(); // y
        let temp3 = a + c; // z

        (temp1, temp2, temp3)
    }
}

/// Combined obfuscation pipeline
pub struct ObfuscationPipeline {
    string_key: Vec<u8>,
}

impl ObfuscationPipeline {
    pub fn new() -> Self {
        Self {
            string_key: StringObfuscator::generate_key(),
        }
    }

    /// Obfuscate a string for storage/transmission
    pub fn obfuscate_string(&self, s: &str) -> Vec<u8> {
        StringObfuscator::encrypt_with_key(s, &self.string_key)
    }

    /// Deobfuscate a previously obfuscated string
    pub fn deobfuscate_string(&self, encrypted: &[u8]) -> String {
        StringObfuscator::decrypt(encrypted, &self.string_key)
    }

    /// Execute code with full obfuscation
    pub fn execute_obfuscated<T, F: Fn() -> T>(&self, f: F) -> T {
        ControlFlowObfuscator::with_bogus_flow(|| DeadCodeInserter::with_dead_code(f))
    }
}

impl Default for ObfuscationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_obfuscation() {
        let original = "secret_string";
        let key = StringObfuscator::generate_key();
        let encrypted = StringObfuscator::encrypt_with_key(original, &key);
        let decrypted = StringObfuscator::decrypt(&encrypted, &key);

        assert_eq!(original, decrypted);
        assert_ne!(encrypted, original.as_bytes());
    }

    #[test]
    fn test_string_obfuscation_default() {
        let original = "test_data";
        let encrypted = StringObfuscator::encrypt(original);
        // Can't decrypt without the key, but ensure it's different
        assert_ne!(encrypted, original.as_bytes());
    }

    #[test]
    fn test_opaque_predicate_true() {
        // Should always be true
        for _ in 0..100 {
            assert!(ControlFlowObfuscator::opaque_predicate_true());
        }
    }

    #[test]
    fn test_opaque_predicate_false() {
        // Should always be false
        for _ in 0..100 {
            assert!(!ControlFlowObfuscator::opaque_predicate_false());
        }
    }

    #[test]
    fn test_bogus_control_flow() {
        let result = ControlFlowObfuscator::with_bogus_flow(|| {
            42
        });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_dead_code_inserter() {
        // Should not panic
        DeadCodeInserter::insert_dead_code();

        let result = DeadCodeInserter::with_dead_code(|| 100);
        assert_eq!(result, 100);
    }

    #[test]
    fn test_flattened_execution() {
        let mut counter = 0;
        ControlFlowObfuscator::flattened_execution(|state| {
            counter += 1;
            match state {
                0 => Some(1),
                1 => Some(2),
                2 => Some(99),
                _ => None,
            }
        });
        assert_eq!(counter, 3); // States 0, 1, 2 (then exits when state == 99)
    }

    #[test]
    fn test_obfuscation_pipeline() {
        let pipeline = ObfuscationPipeline::new();

        let original = "sensitive_data";
        let obfuscated = pipeline.obfuscate_string(original);
        let deobfuscated = pipeline.deobfuscate_string(&obfuscated);

        assert_eq!(original, deobfuscated);
    }

    #[test]
    fn test_execute_obfuscated() {
        let pipeline = ObfuscationPipeline::new();
        let result = pipeline.execute_obfuscated(|| {
            let x = 10;
            let y = 20;
            x + y
        });
        assert_eq!(result, 30);
    }

    #[test]
    fn test_instruction_reorderer() {
        let result = InstructionReorderer::reorder_operations(1, 2, 3);
        assert_eq!(result, (3, 5, 4)); // (1+2, 2+3, 1+3)
    }
}
