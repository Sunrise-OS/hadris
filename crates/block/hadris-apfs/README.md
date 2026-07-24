# hadris-apfs

Incremental APFS support for Hadris.

Current scope:

- no-std friendly on-disk APFS container types
- sync and async container opening over `hadris-storage` block devices
- block 0 superblock parsing and object checksum verification
- foundations for checkpoint/object-map/tree walking
- optional `crypto` feature: software (password/recovery-key) FileVault
  decryption — keybag parsing, PBKDF2 key derivation, RFC 3394 AES
  key-unwrap, and AES-XTS block decryption. This **cannot** decrypt
  Secure-Enclave-sealed volumes (every internal volume on T2 and Apple
  Silicon Macs); their key is only ever released by the SEP after OS-level
  authentication, never by unwrapping bytes found on disk.

Write support is feature-gated and intentionally starts as scaffolding until the
read path is complete enough to validate allocation state safely.
