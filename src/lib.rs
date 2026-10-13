// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

//! A file **content** self_encryptor.
//!
//! This library provides convergent encryption on file-based data and produces a `DataMap` type and
//! several chunks of encrypted data. Each chunk is up to 1MB in size and has an index and a name. This name is the
//! BLAKE3 hash of the content, which allows the chunks to be self-validating.  If size and hash
//! checks are utilised, a high degree of certainty in the validity of the data can be expected.
//!
//! [Project GitHub page](https://github.com/maidsafe/self_encryption).
//!
//! # Examples
//!
//! A working implementation can be found
//! in the "examples" folder of this project.
//!
//! ```
//! use self_encryption::{encrypt, test_helpers::random_bytes};
//!
//! #[tokio::main]
//! async fn main() {
//!     let file_size = 10_000_000;
//!     let bytes = random_bytes(file_size);
//!
//!     if let Ok((_data_map, _encrypted_chunks)) = encrypt(bytes) {
//!         // .. then persist the `encrypted_chunks`.
//!         // Remember to keep `data_map` somewhere safe..!
//!     }
//! }
//! ```
//!
//! Storage of the `Vec<EncryptedChunk>` or `DataMap` is outwith the scope of this
//! library and must be implemented by the user.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![cfg_attr(not(feature = "python"), deny(warnings))]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results
)]
#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    non_camel_case_types
)]
// Doesn't allow casts on constants yet, remove when issue is fixed:
// https://github.com/rust-lang-nursery/rust-clippy/issues/2267
#![allow(clippy::cast_lossless, clippy::decimal_literal_representation)]

mod chunk;
mod cipher;
mod data_map;
mod data_map_index;
mod decrypt;
mod encrypt;
mod error;
/// BLAKE3 content hashing (replaces SHA3-256)
pub mod hash;
#[cfg(feature = "python")]
mod python;
mod stream_decrypt;
mod stream_encrypt;
pub mod test_helpers;
mod utils;

pub use chunk::EncryptedChunk;
pub use decrypt::decrypt_chunk;
use utils::*;
pub use xor_name::XorName;

pub use self::{
    data_map::{ChunkInfo, DataMap},
    data_map_index::DataMapIndex,
    error::{Error, Result},
    stream_decrypt::{streaming_decrypt, streaming_decrypt_with_batch_size, DecryptionStream},
    stream_encrypt::{stream_encrypt, ChunkStream, EncryptionStream},
};
use bytes::Bytes;
use std::{collections::HashMap, sync::LazyLock};

// export these because they are used in our public API.
pub use bytes;
pub use xor_name;

/// Batch size for streaming decrypt chunk fetching.
///
/// Can be overridden by the `STREAM_DECRYPT_BATCH_SIZE` environment variable.
/// Invalid values and `0` fall back to [`DEFAULT_STREAM_DECRYPT_BATCH_SIZE`].
pub static STREAM_DECRYPT_BATCH_SIZE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("STREAM_DECRYPT_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_STREAM_DECRYPT_BATCH_SIZE)
});

/// Default batch size for streaming decrypt chunk fetching.
pub const DEFAULT_STREAM_DECRYPT_BATCH_SIZE: usize = 10;

/// Read the current streaming decrypt batch size.
///
/// This reads the legacy `STREAM_DECRYPT_BATCH_SIZE` environment variable on
/// first use, falling back to [`DEFAULT_STREAM_DECRYPT_BATCH_SIZE`]. New code
/// that needs explicit per-stream tuning should use
/// [`streaming_decrypt_with_batch_size`].
pub fn stream_decrypt_batch_size() -> usize {
    *STREAM_DECRYPT_BATCH_SIZE
}

/// The minimum size (before compression) of data to be self-encrypted, defined as 3B.
pub const MIN_ENCRYPTABLE_BYTES: usize = 3 * MIN_CHUNK_SIZE;

/// The maximum size (before compression) of an individual chunk of a file, defaulting to ~4MiB.
/// Set to 4190208 (4MiB - 4KiB) to leave headroom for occasional compression growth.
pub const MAX_CHUNK_SIZE: usize = match std::option_env!("MAX_CHUNK_SIZE") {
    Some(v) => match usize::from_str_radix(v, 10) {
        Ok(v) => v,
        Err(_err) => panic!("`MAX_CHUNK_SIZE` failed to parse as usize"),
    },
    None => 4_190_208,
};

/// The minimum size (before compression) of an individual chunk of a file, defined as 1B.
pub const MIN_CHUNK_SIZE: usize = 1;
/// Controls the compression-speed vs compression-density tradeoffs.  The higher the quality, the
/// slower the compression.  Range is 0 to 11.
pub const COMPRESSION_QUALITY: i32 = 6;

/// Encrypts a set of bytes and returns the encrypted data together with
/// the data map that is derived from the input data.
pub fn encrypt(bytes: Bytes) -> Result<(DataMap, Vec<EncryptedChunk>)> {
    encrypt_with_child_level(bytes, 0)
}

/// Internal encryption that accepts a child_level for KDF domain separation.
fn encrypt_with_child_level(
    bytes: Bytes,
    child_level: usize,
) -> Result<(DataMap, Vec<EncryptedChunk>)> {
    let file_size = bytes.len();
    if file_size < MIN_ENCRYPTABLE_BYTES {
        return Err(Error::Generic(format!(
            "Too small for self-encryption! Required size at least {MIN_ENCRYPTABLE_BYTES}"
        )));
    }

    let num_chunks = get_num_chunks(file_size);
    if num_chunks < 3 {
        return Err(Error::Generic(
            "File must be large enough to generate at least 3 chunks".to_string(),
        ));
    }

    let mut chunk_infos = Vec::with_capacity(num_chunks);
    let mut first_chunks = Vec::with_capacity(2);
    let mut src_hashes = Vec::with_capacity(num_chunks);
    let mut encrypted_chunks = Vec::with_capacity(num_chunks);

    // Process all chunks
    for chunk_index in 0..num_chunks {
        let (start, end) = get_start_end_positions(file_size, chunk_index);
        let chunk_data = bytes.slice(start..end);
        let src_hash = hash::content_hash(&chunk_data);
        src_hashes.push(src_hash);

        // Store first two chunks for later processing
        if chunk_index < 2 {
            first_chunks.push((chunk_index, chunk_data, src_hash, end - start));
            continue;
        }

        // For chunks 2 onwards, we can encrypt immediately since we have the previous two hashes
        let pki = get_pad_key_and_nonce(chunk_index, &src_hashes, child_level)?;
        let encrypted_content = encrypt::encrypt_chunk(chunk_data, pki)?;
        let dst_hash = hash::content_hash(&encrypted_content);

        encrypted_chunks.push(EncryptedChunk {
            content: encrypted_content,
        });

        chunk_infos.push(ChunkInfo {
            index: chunk_index,
            dst_hash,
            src_hash,
            src_size: end - start,
        });
    }

    // Now process the first two chunks using the complete set of source hashes
    for (chunk_index, chunk_data, src_hash, src_size) in first_chunks {
        let pki = get_pad_key_and_nonce(chunk_index, &src_hashes, child_level)?;
        let encrypted_content = encrypt::encrypt_chunk(chunk_data, pki)?;
        let dst_hash = hash::content_hash(&encrypted_content);

        encrypted_chunks.insert(
            chunk_index,
            EncryptedChunk {
                content: encrypted_content,
            },
        );

        chunk_infos.insert(
            chunk_index,
            ChunkInfo {
                index: chunk_index,
                dst_hash,
                src_hash,
                src_size,
            },
        );
    }

    let data_map = DataMap::new(chunk_infos);

    // Shrink the data map and store additional chunks if needed
    let (shrunk_data_map, _) = shrink_data_map(data_map, |_hash, content| {
        encrypted_chunks.push(EncryptedChunk { content });
        Ok(())
    })?;

    Ok((shrunk_data_map, encrypted_chunks))
}

/// Decrypts a full set of chunks using the provided data map.
///
/// This function takes a data map and a slice of encrypted chunks and decrypts them to recover
/// the original data. It handles both root data maps and child data maps.
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information
/// * `chunks` - The encrypted chunks to decrypt
///
/// # Returns
///
/// * `Result<Bytes>` - The decrypted data or an error if chunks are missing/corrupted
pub(crate) fn decrypt_full_set(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);
    let child_level = data_map.child().unwrap_or(0);

    // Create a mapping of chunk hashes to chunks for efficient lookup
    let chunk_map: HashMap<XorName, &EncryptedChunk> = chunks
        .iter()
        .map(|chunk| (hash::content_hash(&chunk.content), chunk))
        .collect();

    // Get chunks in the order specified by the data map
    let mut sorted_chunks = Vec::with_capacity(data_map.len());
    for info in data_map.infos() {
        let chunk = chunk_map.get(&info.dst_hash).ok_or_else(|| {
            Error::Generic(format!(
                "Chunk with hash {:?} not found in data map",
                info.dst_hash
            ))
        })?;
        sorted_chunks.push(*chunk);
    }

    decrypt::decrypt_sorted_set(src_hashes, &sorted_chunks, child_level)
}

/// Decrypts a range of data from the encrypted chunks.
///
/// # Arguments
/// * `data_map` - The data map containing chunk information
/// * `chunks` - The encrypted chunks to decrypt
/// * `file_pos` - The position within the complete file to start reading from
/// * `len` - Number of bytes to read
///
/// # Returns
/// * `Result<Bytes>` - The decrypted range of data or an error if chunks are missing/corrupted
#[allow(dead_code)]
pub(crate) fn decrypt_range(
    data_map: &DataMap,
    chunks: &[EncryptedChunk],
    file_pos: usize,
    len: usize,
) -> Result<Bytes> {
    let src_hashes = extract_hashes(data_map);

    // Create a mapping of chunk hashes to chunks for efficient lookup
    let chunk_map: HashMap<XorName, &EncryptedChunk> = chunks
        .iter()
        .map(|chunk| (hash::content_hash(&chunk.content), chunk))
        .collect();

    // Get chunk size info
    let file_size = data_map.original_file_size();

    // Calculate which chunks we need based on the range
    let start_chunk = get_chunk_index(file_size, file_pos);
    let end_pos = std::cmp::min(file_pos + len, file_size);
    let end_chunk = get_chunk_index(file_size, end_pos);

    // Get chunks in the order specified by the data map
    let mut sorted_chunks = Vec::new();
    for info in data_map.infos() {
        if info.index >= start_chunk && info.index <= end_chunk {
            let chunk = chunk_map.get(&info.dst_hash).ok_or_else(|| {
                Error::Generic(format!(
                    "Chunk with hash {:?} not found in data map",
                    info.dst_hash
                ))
            })?;
            sorted_chunks.push(*chunk);
        }
    }

    // Decrypt all required chunks
    let mut all_bytes = Vec::new();
    for (idx, chunk) in sorted_chunks.iter().enumerate() {
        let chunk_idx = start_chunk + idx;
        let decrypted = decrypt_chunk(
            chunk_idx,
            &chunk.content,
            &src_hashes,
            data_map.child().unwrap_or(0),
        )?;
        all_bytes.extend_from_slice(&decrypted);
    }

    let bytes = Bytes::from(all_bytes);

    // Calculate the actual offset within our decrypted data
    let chunk_start_pos = get_start_position(file_size, start_chunk);
    let internal_offset = file_pos - chunk_start_pos;

    if internal_offset >= bytes.len() {
        return Ok(Bytes::new());
    }

    // Extract just the range we need from the decrypted data
    let available_len = bytes.len() - internal_offset;
    let range_len = std::cmp::min(len, available_len);
    let range_bytes = bytes.slice(internal_offset..internal_offset + range_len);

    Ok(range_bytes)
}

/// Shrinks a data map by recursively encrypting it until the number of chunks is small enough
/// Returns the final data map and all chunks generated during shrinking
pub fn shrink_data_map<F>(
    mut data_map: DataMap,
    mut store_chunk: F,
) -> Result<(DataMap, Vec<EncryptedChunk>)>
where
    F: FnMut(XorName, Bytes) -> Result<()>,
{
    let mut all_chunks = Vec::new();

    while data_map.len() > 3 {
        let next_child_level = data_map.child().map_or(1, |c| c + 1);
        let bytes = data_map
            .to_bytes()
            .map(Bytes::from)
            .map_err(|e| Error::Generic(format!("Failed to serialize data map: {e}")))?;

        let (mut new_data_map, encrypted_chunks) =
            encrypt_with_child_level(bytes, next_child_level)?;

        // Store and collect chunks
        for chunk in &encrypted_chunks {
            store_chunk(hash::content_hash(&chunk.content), chunk.content.clone())?;
        }
        all_chunks.extend(encrypted_chunks);

        // Tag the DataMap with the child_level used during encryption
        new_data_map = DataMap::with_child(new_data_map.infos().to_vec(), next_child_level);
        data_map = new_data_map;
    }
    Ok((data_map, all_chunks))
}

/// Recursively gets the root data map by decrypting child data maps
/// Takes a chunk retrieval function that handles fetching the encrypted chunks
pub fn get_root_data_map<F>(data_map: DataMap, get_chunk: &mut F) -> Result<DataMap>
where
    F: FnMut(XorName) -> Result<Bytes>,
{
    // Create a cache of found chunks at the top level
    let mut chunk_cache = HashMap::new();

    fn inner_get_root_map<F>(
        data_map: DataMap,
        get_chunk: &mut F,
        chunk_cache: &mut HashMap<XorName, Bytes>,
        depth: usize,
    ) -> Result<DataMap>
    where
        F: FnMut(XorName) -> Result<Bytes>,
    {
        if depth > 100 {
            return Err(Error::Generic(
                "Maximum data map recursion depth exceeded".to_string(),
            ));
        }

        // If this is the root data map (no child level), return it
        if !data_map.is_child() {
            return Ok(data_map);
        }

        // Get all the chunks for this data map using the provided retrieval function
        let mut encrypted_chunks = Vec::new();

        for chunk_info in data_map.infos() {
            let chunk_data = if let Some(cached) = chunk_cache.get(&chunk_info.dst_hash) {
                cached.clone()
            } else {
                let data = get_chunk(chunk_info.dst_hash)?;
                let _ = chunk_cache.insert(chunk_info.dst_hash, data.clone());
                data
            };
            encrypted_chunks.push(EncryptedChunk {
                content: chunk_data,
            });
        }

        // Decrypt the chunks to get the parent data map bytes
        let decrypted_bytes = decrypt_full_set(&data_map, &encrypted_chunks)?;

        // Deserialize into a DataMap
        let parent_data_map = DataMap::from_bytes(&decrypted_bytes)
            .map_err(|e| Error::Generic(format!("Failed to deserialize data map: {e}")))?;

        // Recursively get the root data map
        inner_get_root_map(parent_data_map, get_chunk, chunk_cache, depth + 1)
    }

    // Start the recursive process with our cache
    inner_get_root_map(data_map, get_chunk, &mut chunk_cache, 0)
}

/// Decrypts data using chunks retrieved from any storage backend via the provided retrieval function.
pub fn decrypt(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<Bytes> {
    // Create a mapping of chunk hashes to chunks for efficient lookup
    let chunk_map: HashMap<XorName, &EncryptedChunk> = chunks
        .iter()
        .map(|chunk| (hash::content_hash(&chunk.content), chunk))
        .collect();

    // Helper function to find chunks using our hash map
    let mut get_chunk = |hash| {
        chunk_map
            .get(&hash)
            .map(|chunk| chunk.content.clone())
            .ok_or_else(|| Error::Generic(format!("Chunk not found for hash: {hash:?}")))
    };

    // Get the root map if we're dealing with a child map
    let root_map = if data_map.is_child() {
        get_root_data_map(data_map.clone(), &mut get_chunk)?
    } else {
        data_map.clone()
    };

    // Get only the chunks needed for the root map
    let root_chunks: Vec<EncryptedChunk> = root_map
        .infos()
        .iter()
        .map(|info| {
            chunk_map
                .get(&info.dst_hash)
                .map(|chunk| EncryptedChunk {
                    content: chunk.content.clone(),
                })
                .ok_or_else(|| {
                    Error::Generic(format!("Missing chunk: {}", hex::encode(info.dst_hash)))
                })
        })
        .collect::<Result<_>>()?;

    decrypt_full_set(&root_map, &root_chunks)
}

/// Recursively gets the root data map by decrypting child data maps using parallel chunk retrieval.
///
/// This function works similarly to `get_root_data_map`, but it retrieves chunks in parallel,
/// improving performance when dealing with large data maps or slow storage backends.
///
/// # Arguments
///
/// * `data_map` - The data map to retrieve the root from.
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given a list of XorName hashes.
///
/// # Returns
///
/// * `Result<DataMap>` - The root data map or an error if retrieval or decryption fails.
pub fn get_root_data_map_parallel<F>(data_map: DataMap, get_chunk_parallel: &F) -> Result<DataMap>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    // Create a cache for chunks to avoid redundant retrievals
    let mut chunk_cache = HashMap::new();

    fn inner_get_root_map<F>(
        data_map: DataMap,
        get_chunk_parallel: &F,
        chunk_cache: &mut HashMap<XorName, Bytes>,
        depth: usize,
    ) -> Result<DataMap>
    where
        F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
    {
        if depth > 100 {
            return Err(Error::Generic(
                "Maximum data map recursion depth exceeded".to_string(),
            ));
        }

        // If this is the root data map (no child level), return it
        if !data_map.is_child() {
            return Ok(data_map);
        }

        // Determine which chunks are missing from the cache
        let missing_hashes: Vec<_> = data_map
            .infos()
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .filter(|(_i, hash)| !chunk_cache.contains_key(hash))
            .collect();

        if !missing_hashes.is_empty() {
            let new_chunks = get_chunk_parallel(&missing_hashes)?;
            for ((_i, hash), (_j, chunk_data)) in missing_hashes.iter().zip(new_chunks) {
                let _ = chunk_cache.insert(*hash, chunk_data);
            }
        }

        let encrypted_chunks: Vec<EncryptedChunk> = data_map
            .infos()
            .iter()
            .map(|info| {
                let content = chunk_cache.get(&info.dst_hash).ok_or_else(|| {
                    let dst_hash = info.dst_hash;
                    Error::Generic(format!("Chunk not found for hash: {dst_hash:?}"))
                })?;
                Ok(EncryptedChunk {
                    content: content.clone(),
                })
            })
            .collect::<Result<_>>()?;

        // Decrypt the chunks to get the parent data map bytes
        let decrypted_bytes = decrypt_full_set(&data_map, &encrypted_chunks)?;
        let parent_data_map = DataMap::from_bytes(&decrypted_bytes)
            .map_err(|e| Error::Generic(format!("Failed to deserialize data map: {e}")))?;

        // Recursively get the root data map
        inner_get_root_map(parent_data_map, get_chunk_parallel, chunk_cache, depth + 1)
    }

    // Start the recursive process with our cache
    inner_get_root_map(data_map, get_chunk_parallel, &mut chunk_cache, 0)
}

/// Serializes a data structure using bincode.
///
/// # Arguments
///
/// * `data` - The data structure to serialize, must implement `serde::Serialize`
///
/// # Returns
///
/// * `Result<Vec<u8>>` - The serialized bytes or an error
pub fn serialize<T: serde::Serialize>(data: &T) -> Result<Vec<u8>> {
    bincode::serialize(data).map_err(|e| Error::Generic(format!("Serialization error: {e}")))
}

/// Deserializes bytes into a data structure using bincode.
///
/// # Arguments
///
/// * `bytes` - The bytes to deserialize
///
/// # Returns
///
/// * `Result<T>` - The deserialized data structure or an error
pub fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|e| Error::Generic(format!("Deserialization error: {e}")))
}

/// Verifies and deserializes a chunk by checking its content hash matches the provided name.
///
/// # Arguments
///
/// * `name` - The expected XorName hash of the chunk content
/// * `bytes` - The serialized chunk content to verify
///
/// # Returns
///
/// * `Result<EncryptedChunk>` - The deserialized chunk if verification succeeds
/// * `Error` - If the content hash doesn't match or deserialization fails
pub fn verify_chunk(name: XorName, bytes: &[u8]) -> Result<EncryptedChunk> {
    // Create an EncryptedChunk from the bytes
    let chunk = EncryptedChunk {
        content: Bytes::from(bytes.to_vec()),
    };

    // Calculate the hash of the encrypted content directly
    let calculated_hash = hash::content_hash(chunk.content.as_ref());

    // Verify the hash matches
    if calculated_hash != name {
        return Err(Error::Generic(format!(
            "Chunk content hash mismatch. Expected: {name:?}, Got: {calculated_hash:?}"
        )));
    }

    Ok(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::random_bytes;
    use std::{
        io::Write,
        process::Command,
        sync::{Arc, Mutex},
    };
    use tempfile::NamedTempFile;

    // Helper function to create a data map with specified number of chunks
    #[allow(dead_code)]
    fn create_test_data_map(num_chunks: usize) -> Result<DataMap> {
        let bytes = random_bytes(num_chunks * MIN_CHUNK_SIZE);
        let (data_map, _) = encrypt(bytes)?;
        Ok(data_map)
    }

    #[allow(dead_code)]
    fn create_dummy_data_map(num_chunks: usize) -> DataMap {
        let mut chunks = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            chunks.push(ChunkInfo {
                index: i,
                dst_hash: hash::content_hash(&[i as u8]),
                src_hash: hash::content_hash(&[i as u8]),
                src_size: MIN_CHUNK_SIZE,
            });
        }
        DataMap::new(chunks)
    }

    fn assert_stream_decrypt_batch_size_from_env(
        env_value: Option<&str>,
        expected: usize,
    ) -> Result<()> {
        let mut child = Command::new(std::env::current_exe()?);
        let _ = child
            .arg("--ignored")
            .arg("--exact")
            .arg("tests::stream_decrypt_batch_size_env_child")
            .arg("--nocapture")
            .env(
                "SELF_ENCRYPTION_STREAM_DECRYPT_BATCH_SIZE_EXPECTED",
                expected.to_string(),
            );

        if let Some(value) = env_value {
            let _ = child.env("STREAM_DECRYPT_BATCH_SIZE", value);
        } else {
            let _ = child.env_remove("STREAM_DECRYPT_BATCH_SIZE");
        }

        let output = child.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "child env test failed\nstdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );
        assert!(
            stdout.contains("stream_decrypt_batch_size_env_child observed"),
            "child env test did not run\nstdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );
        Ok(())
    }

    #[test]
    fn test_stream_decrypt_batch_size_env_fallbacks() -> Result<()> {
        assert_stream_decrypt_batch_size_from_env(None, DEFAULT_STREAM_DECRYPT_BATCH_SIZE)?;
        assert_stream_decrypt_batch_size_from_env(
            Some("not-a-number"),
            DEFAULT_STREAM_DECRYPT_BATCH_SIZE,
        )?;
        assert_stream_decrypt_batch_size_from_env(Some("0"), DEFAULT_STREAM_DECRYPT_BATCH_SIZE)?;
        assert_stream_decrypt_batch_size_from_env(Some("64"), 64)?;
        Ok(())
    }

    #[test]
    #[ignore]
    fn stream_decrypt_batch_size_env_child() -> Result<()> {
        let expected = match std::env::var("SELF_ENCRYPTION_STREAM_DECRYPT_BATCH_SIZE_EXPECTED") {
            Ok(expected) => expected.parse::<usize>()?,
            Err(_) => return Ok(()),
        };

        let observed = stream_decrypt_batch_size();
        println!("stream_decrypt_batch_size_env_child observed {observed}");
        assert_eq!(observed, expected);
        Ok(())
    }

    #[test]
    fn test_multiple_levels_of_shrinking() -> Result<()> {
        // Create a temp file with random data
        let bytes = random_bytes(10_000_000);
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(&bytes)?;

        let storage = HashMap::new();
        let storage_clone = Arc::new(Mutex::new(storage));

        let store = move |hash: XorName, content: Bytes| -> Result<()> {
            let _ = storage_clone.lock().unwrap().insert(hash, content.to_vec());
            Ok(())
        };

        // Use standard encryption which supports shrinking
        let (data_map, encrypted_chunks) = encrypt(bytes)?;

        // Store the chunks
        for chunk in &encrypted_chunks {
            store(hash::content_hash(&chunk.content), chunk.content.clone())?;
        }
        assert!(data_map.chunk_identifiers.len() <= 3);

        Ok(())
    }

    #[test]
    fn test_streaming_encrypt_4mb_file() -> Result<()> {
        // Create test data - exactly 4MB
        let file_size = 4 * 1024 * 1024;
        let bytes = random_bytes(file_size);

        // Create storage for encrypted chunks
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let storage_clone = storage.clone();

        // Store function that also prints chunk info for debugging
        let store = move |hash: XorName, content: Bytes| -> Result<()> {
            println!(
                "Storing chunk: {} (size: {}) at index {}",
                hex::encode(hash),
                content.len(),
                storage_clone.lock().unwrap().len()
            );
            let _ = storage_clone.lock().unwrap().insert(hash, content.to_vec());
            Ok(())
        };

        // First encrypt the data directly to get ALL chunks
        let (data_map, initial_chunks) = encrypt(bytes.clone())?;

        println!("Initial data map has {} chunks", data_map.len());
        println!("Data map child level: {:?}", data_map.child());

        // Start with all initial chunks
        let mut all_chunks = Vec::new();
        all_chunks.extend(initial_chunks);

        // Store all chunks
        for chunk in &all_chunks {
            let hash = hash::content_hash(&chunk.content);
            store(hash, chunk.content.clone())?;
        }

        // Now do a shrink operation
        let mut store_memory = store.clone();
        let (shrunk_map, shrink_chunks) = shrink_data_map(data_map.clone(), &mut store_memory)?;
        println!("Got {} new chunks from shrinking", shrink_chunks.len());

        // Add shrink chunks to our collection
        all_chunks.extend(shrink_chunks);

        println!("\nFinal Data Map Info:");
        println!("Number of chunks: {}", shrunk_map.len());
        println!("Original file size: {file_size}");
        println!("Is child: {}", shrunk_map.is_child());

        for (i, info) in shrunk_map.infos().iter().enumerate() {
            println!(
                "Chunk {}: index={}, src_size={}, src_hash={}, dst_hash={}",
                i,
                info.index,
                info.src_size,
                hex::encode(info.src_hash),
                hex::encode(info.dst_hash)
            );
        }

        // Print all stored chunks
        println!("\nStored Chunks:");
        let stored = storage.lock().unwrap();
        for (hash, content) in stored.iter() {
            println!("Hash: {} (size: {})", hex::encode(hash), content.len());
        }

        // Create chunk retrieval function for streaming_decrypt
        let stored_clone = stored.clone();
        let get_chunk_parallel = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            hashes
                .iter()
                .map(|(i, hash)| {
                    stored_clone
                        .get(hash)
                        .map(|data| (*i, Bytes::from(data.clone())))
                        .ok_or_else(|| {
                            Error::Generic(format!("Missing chunk: {}", hex::encode(hash)))
                        })
                })
                .collect()
        };

        // Decrypt using streaming_decrypt
        let decrypt_stream = streaming_decrypt(&shrunk_map, &get_chunk_parallel)?;
        let decrypted = decrypt_stream.range_full()?;

        assert_eq!(decrypted.len(), file_size);
        assert_eq!(&decrypted[..], &bytes[..]);

        Ok(())
    }
}
