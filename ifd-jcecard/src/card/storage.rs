//! Card state storage
//!
//! Handles persistent JSON storage of card state, compatible with the Python format.

use std::fs;
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use log::{info, warn, debug};

use super::state::{CardState, PINData};

/// Handles persistent storage of card state
pub struct CardDataStore {
    storage_dir: PathBuf,
    state_file: PathBuf,
    pub state: CardState,
}

impl CardDataStore {
    const DEFAULT_STATE_FILE: &'static str = "card_state.json";

    /// Get the default storage directory
    fn get_default_storage_dir() -> PathBuf {
        // Check environment variable first
        if let Ok(path) = std::env::var("JCECARD_STORAGE_DIR") {
            return PathBuf::from(path);
        }
        // Use ~/.jcecard as default (matching Python behavior for user processes)
        if let Some(home) = dirs::home_dir() {
            return home.join(".jcecard");
        }
        // Fallback to /var/lib/jcecard
        PathBuf::from("/var/lib/jcecard")
    }

    /// Create a new card data store
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        let storage_dir = storage_path.unwrap_or_else(Self::get_default_storage_dir);
        let state_file = storage_dir.join(Self::DEFAULT_STATE_FILE);

        Self {
            storage_dir,
            state_file,
            state: CardState::default(),
        }
    }

    /// Ensure the storage directory exists
    fn ensure_storage_dir(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.storage_dir)?;
        // Try to set permissions (may fail if not owner)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.storage_dir, fs::Permissions::from_mode(0o755));
        }
        Ok(())
    }

    /// Load card state from storage
    ///
    /// Returns true if state was loaded, false if new state was created
    pub fn load(&mut self) -> bool {
        if !self.state_file.exists() {
            info!("No existing card state, creating new");
            self.state = CardState::default();
            self.initialize_default_pins();
            return false;
        }

        match fs::read_to_string(&self.state_file) {
            Ok(content) => {
                match serde_json::from_str(&content) {
                    Ok(state) => {
                        self.state = state;
                        info!("Loaded card state from {:?}", self.state_file);
                        true
                    }
                    Err(e) => {
                        warn!("Failed to parse card state: {}", e);
                        self.state = CardState::default();
                        self.initialize_default_pins();
                        false
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read card state file: {}", e);
                self.state = CardState::default();
                self.initialize_default_pins();
                false
            }
        }
    }

    /// Save card state to storage
    pub fn save(&self) -> bool {
        if let Err(e) = self.ensure_storage_dir() {
            warn!("Failed to create storage directory: {}", e);
            return false;
        }

        match serde_json::to_string_pretty(&self.state) {
            Ok(json) => {
                match fs::write(&self.state_file, json) {
                    Ok(()) => {
                        // Try to set file permissions
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(&self.state_file, fs::Permissions::from_mode(0o644));
                        }
                        debug!("Saved card state to {:?}", self.state_file);
                        true
                    }
                    Err(e) => {
                        warn!("Failed to write card state: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                warn!("Failed to serialize card state: {}", e);
                false
            }
        }
    }

    /// Initialize default PIN hashes
    fn initialize_default_pins(&mut self) {
        // Default PW1: "123456"
        self.state.pin_data.pw1_hash = Self::hash_pin("123456");
        self.state.pin_data.pw1_length = 6;

        // Default PW3: "12345678"
        self.state.pin_data.pw3_hash = Self::hash_pin("12345678");
        self.state.pin_data.pw3_length = 8;
    }

    /// Hash a PIN for storage using SHA-256
    pub fn hash_pin(pin: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(pin.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Reset card to factory defaults
    pub fn reset_to_factory(&mut self) {
        self.state = CardState::default();
        self.initialize_default_pins();
        self.save();
        info!("Card reset to factory defaults");
    }

    /// Get a reference to the current card state
    pub fn get_state(&self) -> &CardState {
        &self.state
    }

    /// Get a mutable reference to the current card state
    pub fn get_state_mut(&mut self) -> &mut CardState {
        &mut self.state
    }

    /// Create a new temporary card data store for testing
    #[cfg(test)]
    pub fn new_temp() -> Self {
        let temp_dir = std::env::temp_dir().join(format!("jcecard_test_{}", std::process::id()));
        let mut store = Self::new(Some(temp_dir));
        store.load();
        store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_new_store() {
        let temp_dir = TempDir::new().unwrap();
        let mut store = CardDataStore::new(Some(temp_dir.path().to_path_buf()));

        // Should create new state with default PINs
        assert!(!store.load());
        assert!(!store.state.pin_data.pw1_hash.is_empty());
        assert!(!store.state.pin_data.pw3_hash.is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let mut store = CardDataStore::new(Some(temp_dir.path().to_path_buf()));
        store.load();

        // Modify state
        store.state.signature_counter = 42;
        store.state.cardholder.name = "Test User".to_string();

        // Save
        assert!(store.save());

        // Load in new store
        let mut store2 = CardDataStore::new(Some(temp_dir.path().to_path_buf()));
        assert!(store2.load());
        assert_eq!(store2.state.signature_counter, 42);
        assert_eq!(store2.state.cardholder.name, "Test User");
    }

    #[test]
    fn test_hash_pin() {
        let hash1 = CardDataStore::hash_pin("123456");
        let hash2 = CardDataStore::hash_pin("123456");
        let hash3 = CardDataStore::hash_pin("654321");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 32); // SHA-256
    }

    #[test]
    fn test_reset_to_factory() {
        let temp_dir = TempDir::new().unwrap();
        let mut store = CardDataStore::new(Some(temp_dir.path().to_path_buf()));
        store.load();

        // Modify state
        store.state.signature_counter = 100;
        store.state.terminated = true;
        store.save();

        // Reset
        store.reset_to_factory();

        assert_eq!(store.state.signature_counter, 0);
        assert!(!store.state.terminated);
    }
}
