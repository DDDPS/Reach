use super::*;

/// Tests run against an in-memory keychain that keeps what is written,
/// never the OS one (see keychain_entry_in).
#[test]
fn the_test_keychain_keeps_what_is_written() {
    let entry = keychain_entry_in("reach-keychain-test", "user-a").unwrap();
    entry.set_password("value").unwrap();
    let again = keychain_entry_in("reach-keychain-test", "user-a").unwrap();
    assert_eq!(again.get_password().unwrap(), "value");
    again.delete_credential().unwrap();
    assert!(keychain_entry_in("reach-keychain-test", "user-a").unwrap().get_password().is_err());
}

/// A reset removes the identity's key: it must not stay behind able to
/// open what the identity encrypted.
#[tokio::test]
async fn a_reset_takes_the_identity_key_with_it() {
    let dir = std::env::temp_dir().join(format!("reach-reset-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mgr = VaultManager::new(dir.clone());
    let test_password = format!(
        "reset-test-pass-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    mgr.init_identity(&test_password).await.unwrap();
    let uuid = mgr.user_uuid.clone().unwrap();
    assert!(get_key_from_keychain(&uuid).is_ok(), "the identity stored its key");
    mgr.reset().await.unwrap();
    assert!(get_key_from_keychain(&uuid).is_err(), "the key outlived the reset");
    let _ = std::fs::remove_dir_all(&dir);
}
