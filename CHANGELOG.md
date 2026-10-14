# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

*When editing this file, please respect a line length of 100.*

## [0.36.2] - 2026-10-13

### Added
- `DataMapIndex` gives random access to a `DataMap`'s content with `u64` positions on every
  platform, including 32-bit targets such as `wasm32`. It does no I/O: it lists the chunks
  overlapping a byte range and decrypts single chunks, checking each against the size and source
  hash the map declares. Decompression stops at the declared size, so crafted chunks cannot expand
  beyond it.

### Changed
- `DecryptionStream` is built on `DataMapIndex`. Random access uses `u64` positions and binary
  searches instead of `usize` sums and linear scans, so it no longer overflows on 32-bit targets,
  and every decrypted chunk is checked against its declared size and hash. Construction fails for
  a map whose chunk indices are not exactly `0..n`.
- On 32-bit targets, `DecryptionStream::file_size` reports `usize::MAX` for content larger than
  `usize::MAX` bytes; `DataMapIndex::file_size` gives the exact size.

### Fixed
- `DecryptionStream` fails when the fetch callback omits a chunk. Before, `get_range` joined the
  remaining chunks into wrong content, and iteration ended early as if the content were complete.

## [0.36.1] - 2026-10-06

### Changed
- Relicensed from GPL-3.0 with a linking exception to MIT OR Apache-2.0, at your option. The
  `LICENSE` file is replaced by `LICENSE-MIT` and `LICENSE-APACHE`, and the crate, Python and
  Node.js package metadata declare `MIT OR Apache-2.0`. The last release under GPL-3.0 with the
  linking exception is 0.36.0.

## [0.36.0] - 2026-05-13

### Added
- Added `streaming_decrypt_with_batch_size` and `DecryptionStream::new_with_batch_size` for
  per-stream tuning of decrypt chunk fetch batches.
- Added `DEFAULT_STREAM_DECRYPT_BATCH_SIZE` and `stream_decrypt_batch_size` to expose the default
  stream decrypt batch size.

### Changed
- `streaming_decrypt` continues to use `STREAM_DECRYPT_BATCH_SIZE`, but invalid values and `0` now
  fall back to the default batch size.

## [0.35.0] - 2026-03-13

### Added
- Post-quantum cryptography support.
- BLAKE3-based KDF for nonce derivation, improving cryptographic safety.

### Changed
- Reduced MAX_CHUNK_SIZE to 4190208 bytes to provide compression headroom.
- Child level is now threaded through DecryptionStream and used in KDF.
- Improved Python binding docs and updated TypeScript type definitions.

### Removed
- Legacy v0 DataMap format support has been removed.
- Removed several storage-coupled APIs from the public interface:
  `encrypt_from_file`, `decrypt_from_storage`, `streaming_encrypt_from_file`,
  `streaming_encrypt_datamaps_from_file`, and `streaming_decrypt_from_storage`.

### Fixed
- Improved error handling: eliminated swallowed errors and dead code.
- Fixed boundary underflow test assertions to use local max_chunk_size.

## [0.34.3] - 2025-11-27

### Changed
- Avoid holding individual file handler for each chunk. This resolved an issue we found with long
  downloads when multiple `ant` instances were running at the same time.

## [0.34.2] - 2025-10-08

### Changed
- Max chunk size is now set to 4MB by default. This is the default currently being used in
  production and we are setting it here to avoid mistakes when building binaries that depend on self
  encryption.

## [0.34.1] - 2025-09-09

### Fixed
- random streaming decryption handling different MAX_CHUNK_SIZE scheme.

## [0.34.0] - 2025-09-05

### Added
- Easy-to-use streaming functions: new `stream_encrypt` and `streaming_decrypt` functions provide 
  simplified APIs for streaming encryption/decryption without requiring manual stream management.
- In-memory streaming encryption: streaming encryption now operates entirely in memory, 
  eliminating disk I/O dependencies for better performance.
- Random access streaming decryption: added random access functionality for streaming decryption,
  enabling flexible data retrieval patterns.

### Changed
- Streaming API improvements: greatly enhanced streaming functionality with better memory 
  management and performance optimizations.
- Code organization: consolidated streaming functionality and removed legacy streaming code for 
  better maintainability.

### Removed
- Legacy streaming implementation: removed outdated stream_old code as part of codebase cleanup.

## [0.33.0] - 2025-08-12

### Fixed
- Streaming decryption: resolved issue where `streaming_decrypt_from_storage` resulted in 
  repeated content due to file append behavior.
- Streaming decryption: corrected streaming behavior to properly process chunks in ordered 
  batches for memory-efficient decryption.

### Changed
- Parallel chunk retrieval function signature: `streaming_decrypt_from_storage` now expects
  chunk retrieval functions to accept and return index-hash tuples `(usize, XorName)` instead
  of just hashes, enabling proper ordering during batch processing [BREAKING].

## [0.32.0] - 2025-08-05

### Added
- Node.js bindings: complete Node.js binding implementation with TypeScript definitions.
- Streaming encrypt for Node.js: added streaming encryption functionality for Node.js bindings.
- XorName utilities for Node.js: added `XorName::to_hex` method and native type support.
- Chunk verification for Node.js: added `verify_chunk` function for Node.js bindings.
- Constants export for Node.js: export MIN_CHUNK_SIZE, MAX_CHUNK_SIZE, and other constants.
- DataMap backward compatibility: added support for deserializing old DataMap format while 
  maintaining new struct format with comprehensive fallback support.
- Enhanced testing: added extensive tests for DataMap backward compatibility scenarios.
- Semi-automated release workflow: new human-reviewed release process with manual triggering.

### Changed
- DataMap binary format: now includes version byte for future compatibility [BREAKING].
- MAX_CHUNK_SIZE constant: changed from lazy_static to proper const [BREAKING].
- Node.js API improvements: more native argument handling and better type integration.
- Python bindings: return `Bytes` instead of `List` for better performance.
- Dependencies: removed unused dependencies (num_cpus, tiny_keccak, lazy_static).
- CI/CD improvements: renamed pr.yml to merge.yml, removed commit linting and cargo fmt 
  constraints, added comprehensive Node.js workflows.
- Code quality: fixed 13 clippy format string warnings, applied rustfmt formatting.

### Fixed
- Python bindings: resolved clippy format string warnings in Python bindings.
- Documentation: removed Python examples using nonexistent functions.
- Build system: properly defined pyo3 as optional dependency.
- CI workflows: fixed Node.js CI workflows and NPM package publishing.

### Removed
- Automated workflows: removed automated version bumping and changelog generation workflows.
- Dependencies: removed unused num_cpus, tiny_keccak, and lazy_static dependencies.
- Legacy code: cleaned up old automated changelog entries.
- PR constraints: removed PR size limit check and commit linting requirements.
