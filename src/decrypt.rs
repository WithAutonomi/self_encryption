// Copyright 2021 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use crate::{cipher, utils::get_pad_key_and_nonce, utils::xor, EncryptedChunk, Error, Result};
use brotli::Decompressor;
use bytes::Bytes;
use rayon::prelude::*;
use std::io::{Cursor, Read};
use xor_name::XorName;

/// Internal buffer of the streaming decompressor, as `brotli::BrotliDecompress` uses.
const DECOMPRESS_BUFFER_BYTES: usize = 4096;

// encrypted_Chunks are sorted !!
pub fn decrypt_sorted_set(
    src_hashes: Vec<XorName>,
    encrypted_chunks: &[&EncryptedChunk],
    child_level: usize,
) -> Result<Bytes> {
    // Decrypt chunks in parallel, then concatenate in order
    let decrypted_chunks: Vec<Bytes> = encrypted_chunks
        .par_iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            decrypt_chunk(chunk_index, &chunk.content, &src_hashes, child_level)
        })
        .collect::<Result<Vec<_>>>()?;

    let total_len = decrypted_chunks.iter().map(|c| c.len()).sum();
    let mut all_bytes = Vec::with_capacity(total_len);
    for chunk in &decrypted_chunks {
        all_bytes.extend_from_slice(chunk);
    }

    Ok(Bytes::from(all_bytes))
}

/// Decrypt a chunk, given the index of that chunk in the sequence of chunks,
/// and the raw encrypted content.
pub fn decrypt_chunk(
    chunk_index: usize,
    content: &Bytes,
    src_hashes: &[XorName],
    child_level: usize,
) -> Result<Bytes> {
    decrypt_chunk_bounded(chunk_index, content, src_hashes, child_level, usize::MAX)
}

/// As [`decrypt_chunk`], but fails rather than decompress more than
/// `max_size` bytes.
pub(crate) fn decrypt_chunk_bounded(
    chunk_index: usize,
    content: &Bytes,
    src_hashes: &[XorName],
    child_level: usize,
    max_size: usize,
) -> Result<Bytes> {
    let pki = get_pad_key_and_nonce(chunk_index, src_hashes, child_level)?;
    let (pad, key, nonce) = pki;

    // First remove the XOR obfuscation
    let xored = xor(content, &pad);

    // Then decrypt the content
    let decrypted = cipher::decrypt(xored, &key, &nonce)?;

    // Finally decompress, reading one byte past the bound to detect an overrun
    let mut decompressed = Vec::new();
    let _ = Decompressor::new(Cursor::new(&decrypted), DECOMPRESS_BUFFER_BYTES)
        .take((max_size as u64).saturating_add(1))
        .read_to_end(&mut decompressed)
        .map_err(|_| Error::Compression)?;
    if decompressed.len() > max_size {
        return Err(Error::Generic(format!(
            "chunk {chunk_index} decompresses to more than {max_size} bytes"
        )));
    }

    Ok(Bytes::from(decompressed))
}
