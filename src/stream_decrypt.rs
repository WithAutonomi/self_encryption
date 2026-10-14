// Copyright 2025 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

//! Streaming decryption functionality for memory-efficient processing of large encrypted files.

use crate::{
    get_root_data_map_parallel, stream_decrypt_batch_size, DataMap, DataMapIndex, Error, Result,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ops::Range;
use xor_name::XorName;

/// Iterator that yields decrypted chunks as `Bytes` in streaming fashion.
///
/// This provides memory-efficient decryption by processing chunks in batches
/// and yielding them one at a time without buffering the entire file.
/// The configured batch size caps the number of chunk hashes passed to each
/// fetch callback invocation for both sequential iteration and random-access
/// range reads.
///
/// In addition to sequential streaming, this struct also supports random access
/// to any byte range within the encrypted file using methods like `get_range()`,
/// `range()`, and other convenience methods.
pub struct DecryptionStream<F> {
    index: DataMapIndex,
    get_chunk_parallel: F,
    current_batch_start: usize,
    current_batch_chunks: Vec<Bytes>,
    current_batch_index: usize,
    batch_size: usize,
}

impl<F> DecryptionStream<F>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    /// Creates a new streaming decrypt iterator.
    ///
    /// # Arguments
    ///
    /// * `data_map` - The data map containing chunk information
    /// * `get_chunk_parallel` - Function to retrieve chunks in parallel
    pub fn new(data_map: &DataMap, get_chunk_parallel: F) -> Result<Self> {
        Self::new_with_batch_size(data_map, get_chunk_parallel, stream_decrypt_batch_size())
    }

    /// Creates a new streaming decrypt iterator with an explicit batch size.
    ///
    /// The batch size limits how many chunks are fetched/decrypted per
    /// callback invocation. This applies to sequential iterator consumption
    /// and to random-access APIs such as [`Self::get_range`] and
    /// [`Self::range`]. Range APIs still return the complete requested byte
    /// range; large ranges may therefore perform multiple batched fetches.
    ///
    /// # Arguments
    ///
    /// * `data_map` - The data map containing chunk information
    /// * `get_chunk_parallel` - Function to retrieve chunks in parallel
    /// * `batch_size` - Number of chunks to fetch/decrypt per batch. Must be greater than 0.
    pub fn new_with_batch_size(
        data_map: &DataMap,
        get_chunk_parallel: F,
        batch_size: usize,
    ) -> Result<Self> {
        if batch_size == 0 {
            return Err(crate::Error::Generic(
                "stream decrypt batch size must be > 0".to_string(),
            ));
        }

        let root_map = if data_map.is_child() {
            get_root_data_map_parallel(data_map.clone(), &get_chunk_parallel)?
        } else {
            data_map.clone()
        };

        Ok(Self {
            index: DataMapIndex::new(&root_map)?,
            get_chunk_parallel,
            current_batch_start: 0,
            current_batch_chunks: Vec::new(),
            current_batch_index: 0,
            batch_size,
        })
    }

    /// Fetches and decrypts the next batch of chunks.
    fn fetch_next_batch(&mut self) -> Result<bool> {
        let chunk_infos = self.index.infos();
        if self.current_batch_start >= chunk_infos.len() {
            return Ok(false); // No more chunks
        }

        let batch_end = self
            .current_batch_start
            .saturating_add(self.batch_size)
            .min(chunk_infos.len());
        let batch_infos = chunk_infos
            .get(self.current_batch_start..batch_end)
            .ok_or_else(|| {
                Error::Generic(format!(
                    "batch range {}..{} out of bounds for chunk_infos (len {})",
                    self.current_batch_start,
                    batch_end,
                    chunk_infos.len()
                ))
            })?;

        // Extract chunk hashes for this batch
        let batch_hashes: Vec<_> = batch_infos
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .collect();

        self.current_batch_chunks = self.fetch_and_decrypt(&batch_hashes)?;
        self.current_batch_start = batch_end;
        self.current_batch_index = 0;

        Ok(true)
    }

    /// Fetches one batch and decrypts it in batch order, failing if the
    /// callback omits a requested chunk.
    fn fetch_and_decrypt(&self, batch_hashes: &[(usize, XorName)]) -> Result<Vec<Bytes>> {
        let mut fetched_chunks: HashMap<usize, Bytes> = (self.get_chunk_parallel)(batch_hashes)?
            .into_iter()
            .collect();
        batch_hashes
            .iter()
            .map(|(chunk_index, _)| {
                let encrypted_content = fetched_chunks.remove(chunk_index).ok_or_else(|| {
                    Error::Generic(format!("chunk {chunk_index} missing from fetched chunks"))
                })?;
                self.index.decrypt_chunk(*chunk_index, &encrypted_content)
            })
            .collect()
    }

    /// Returns the original file size for random access operations.
    ///
    /// On 32-bit targets a file larger than `usize::MAX` bytes reports
    /// `usize::MAX`; [`DataMapIndex::file_size`] gives the exact size.
    pub fn file_size(&self) -> usize {
        usize::try_from(self.index.file_size()).unwrap_or(usize::MAX)
    }

    /// Decrypts and returns a specific byte range from the encrypted data.
    ///
    /// This method provides random access to any portion of the encrypted file
    /// without requiring sequential iteration through all preceding chunks.
    ///
    /// # Arguments
    ///
    /// * `start` - The starting byte position (inclusive)
    /// * `len` - The number of bytes to read
    ///
    /// # Returns
    ///
    /// * `Result<Bytes>` - The decrypted range of data or an error if chunks are missing/corrupted
    ///
    /// # Example
    ///
    /// ```rust
    /// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes, hash::content_hash};
    /// use bytes::Bytes;
    /// use xor_name::XorName;
    /// use std::collections::HashMap;
    ///
    /// # fn main() -> self_encryption::Result<()> {
    /// // Create some test data and encrypt it
    /// let original_data = random_bytes(10000);
    /// let (data_map, encrypted_chunks) = encrypt(original_data)?;
    ///
    /// // Create a simple storage backend
    /// let mut storage = HashMap::new();
    /// for chunk in encrypted_chunks {
    ///     let hash = content_hash(&chunk.content);
    ///     storage.insert(hash, chunk.content.to_vec());
    /// }
    ///
    /// // Create chunk retrieval function
    /// let get_chunks = |hashes: &[(usize, XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
    ///     let mut results = Vec::new();
    ///     for &(index, hash) in hashes {
    ///         if let Some(data) = storage.get(&hash) {
    ///             results.push((index, Bytes::from(data.clone())));
    ///         }
    ///     }
    ///     Ok(results)
    /// };
    ///
    /// // Create streaming decrypt instance
    /// let stream = streaming_decrypt(&data_map, get_chunks)?;
    ///
    /// // Random access: get bytes 1000-2000
    /// let range_data = stream.get_range(1000, 1000)?;
    /// println!("Got {} bytes from range 1000-2000", range_data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_range(&self, start: usize, len: usize) -> Result<Bytes> {
        let start = start as u64;
        let end = start.saturating_add(len as u64).min(self.index.file_size());
        if start >= end {
            return Ok(Bytes::new());
        }

        // Collect the hashes of the chunks holding the range, in index order
        let chunks = self.index.chunks_overlapping(start..end);
        let required_hashes: Vec<_> = self.index.infos()[chunks.clone()]
            .iter()
            .map(|info| (info.index, info.dst_hash))
            .collect();

        // Decrypt the chunks in order and collect the bytes
        let mut all_bytes = Vec::new();
        for batch_hashes in required_hashes.chunks(self.batch_size) {
            for decrypted in self.fetch_and_decrypt(batch_hashes)? {
                all_bytes.extend_from_slice(&decrypted);
            }
        }

        // Both offsets lie within the fetched chunks, whose bytes fit in memory
        let chunks_start = self.index.chunk_range(chunks.start).start;
        let from = (start - chunks_start) as usize;
        let to = (end - chunks_start) as usize;
        Ok(Bytes::from(all_bytes).slice(from..to))
    }
}

impl<F> Iterator for DecryptionStream<F>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    type Item = Result<Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        // If we've consumed all chunks in the current batch, fetch the next batch
        if self.current_batch_index >= self.current_batch_chunks.len() {
            match self.fetch_next_batch() {
                Ok(has_more) => {
                    if !has_more {
                        return None; // No more chunks available
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }

        // Return the next chunk from the current batch
        match self.current_batch_chunks.get(self.current_batch_index) {
            Some(chunk) => {
                let chunk = chunk.clone();
                self.current_batch_index += 1;
                Some(Ok(chunk))
            }
            None => None,
        }
    }
}

impl<F> DecryptionStream<F>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    /// Convenience method to get a range using Range syntax.
    ///
    /// # Example
    /// ```rust
    /// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes, hash::content_hash};
    /// use bytes::Bytes;
    /// use xor_name::XorName;
    /// use std::collections::HashMap;
    ///
    /// # fn main() -> self_encryption::Result<()> {
    /// let original_data = random_bytes(10000);
    /// let (data_map, encrypted_chunks) = encrypt(original_data)?;
    /// let mut storage = HashMap::new();
    /// for chunk in encrypted_chunks {
    ///     let hash = content_hash(&chunk.content);
    ///     storage.insert(hash, chunk.content.to_vec());
    /// }
    /// let get_chunks = |hashes: &[(usize, XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
    ///     let mut results = Vec::new();
    ///     for &(index, hash) in hashes {
    ///         if let Some(data) = storage.get(&hash) {
    ///             results.push((index, Bytes::from(data.clone())));
    ///         }
    ///     }
    ///     Ok(results)
    /// };
    /// let stream = streaming_decrypt(&data_map, get_chunks)?;
    /// let _chunk_bytes = stream.range(1000..2000)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn range(&self, range: Range<usize>) -> Result<Bytes> {
        let len = range.end.saturating_sub(range.start);
        self.get_range(range.start, len)
    }

    /// Convenience method to get a range from a starting position to the end of the file.
    pub fn range_from(&self, start: usize) -> Result<Bytes> {
        let file_size = self.file_size();
        let len = file_size.saturating_sub(start);
        self.get_range(start, len)
    }

    /// Convenience method to get a range from the beginning of the file to an end position.
    pub fn range_to(&self, end: usize) -> Result<Bytes> {
        self.get_range(0, end)
    }

    /// Convenience method to get the entire file content.
    pub fn range_full(&self) -> Result<Bytes> {
        let file_size = self.file_size();
        self.get_range(0, file_size)
    }

    /// Convenience method to get an inclusive range.
    pub fn range_inclusive(&self, start: usize, end: usize) -> Result<Bytes> {
        let len = end.saturating_sub(start) + 1; // +1 because inclusive
        self.get_range(start, len)
    }
}

/// Creates a streaming decrypt iterator that yields decrypted chunks as `Bytes`.
///
/// This function provides memory-efficient decryption by processing chunks in batches
/// and yielding them one at a time. It's ideal for large files where loading the entire
/// decrypted content into memory at once would be impractical.
///
/// The returned `DecryptionStream` struct supports both sequential iteration and random
/// access to any byte range within the encrypted file.
///
/// # Arguments
///
/// * `data_map` - The data map containing chunk information
/// * `get_chunk_parallel` - A function that retrieves chunks in parallel given chunk hashes
///
/// # Returns
///
/// * `Result<DecryptionStream<F>>` - An iterator that yields `Result<Bytes>` for each decrypted chunk
///
/// # Examples
///
/// ## Sequential Processing
///
/// ```rust
/// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes, hash::content_hash};
/// use bytes::Bytes;
/// use xor_name::XorName;
/// use std::collections::HashMap;
///
/// # fn main() -> self_encryption::Result<()> {
/// // Create some test data and encrypt it
/// let original_data = random_bytes(10000);
/// let (data_map, encrypted_chunks) = encrypt(original_data)?;
///
/// // Create a simple storage backend
/// let mut storage = HashMap::new();
/// for chunk in encrypted_chunks {
///     let hash = content_hash(&chunk.content);
///     storage.insert(hash, chunk.content.to_vec());
/// }
///
/// // Create chunk retrieval function
/// let get_chunks = |hashes: &[(usize, XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
///     let mut results = Vec::new();
///     for &(index, hash) in hashes {
///         if let Some(data) = storage.get(&hash) {
///             results.push((index, Bytes::from(data.clone())));
///         }
///     }
///     Ok(results)
/// };
///
/// // Create streaming decrypt iterator
/// let stream = streaming_decrypt(&data_map, get_chunks)?;
///
/// // Process each decrypted chunk sequentially
/// for chunk_result in stream {
///     match chunk_result {
///         Ok(chunk_bytes) => {
///             println!("Decrypted chunk of {} bytes", chunk_bytes.len());
///         }
///         Err(e) => {
///             eprintln!("Error decrypting chunk: {}", e);
///             break;
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Random Access
///
/// ```rust
/// use self_encryption::{streaming_decrypt, encrypt, test_helpers::random_bytes, hash::content_hash};
/// use bytes::Bytes;
/// use xor_name::XorName;
/// use std::collections::HashMap;
///
/// # fn main() -> self_encryption::Result<()> {
/// let original_data = random_bytes(10000);
/// let (data_map, encrypted_chunks) = encrypt(original_data)?;
///
/// let mut storage = HashMap::new();
/// for chunk in encrypted_chunks {
///     let hash = content_hash(&chunk.content);
///     storage.insert(hash, chunk.content.to_vec());
/// }
///
/// let get_chunks = |hashes: &[(usize, XorName)]| -> self_encryption::Result<Vec<(usize, Bytes)>> {
///     let mut results = Vec::new();
///     for &(index, hash) in hashes {
///         if let Some(data) = storage.get(&hash) {
///             results.push((index, Bytes::from(data.clone())));
///         }
///     }
///     Ok(results)
/// };
///
/// let stream = streaming_decrypt(&data_map, get_chunks)?;
///
/// // Random access examples
/// let chunk_bytes = stream.range(1000..2000)?;
/// println!("Decrypted range 1000-2000: {} bytes", chunk_bytes.len());
///
/// let from_middle = stream.range_from(5000)?;
/// println!("From byte 5000 to end: {} bytes", from_middle.len());
///
/// let first_kilobyte = stream.range_to(1024)?;
/// println!("First 1024 bytes: {} bytes", first_kilobyte.len());
///
/// // Direct range access with get_range
/// let specific_range = stream.get_range(2000, 500)?;
/// println!("500 bytes starting at position 2000: {} bytes", specific_range.len());
/// # Ok(())
/// # }
/// ```
pub fn streaming_decrypt<F>(
    data_map: &DataMap,
    get_chunk_parallel: F,
) -> Result<DecryptionStream<F>>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    DecryptionStream::new(data_map, get_chunk_parallel)
}

/// Creates a streaming decrypt iterator with an explicit batch size.
///
/// This is the preferred API for callers that need to tune download
/// throughput without relying on process-wide environment variables. The
/// batch size caps the number of chunks requested from the fetch callback per
/// invocation for both iterator reads and random-access range reads.
pub fn streaming_decrypt_with_batch_size<F>(
    data_map: &DataMap,
    get_chunk_parallel: F,
    batch_size: usize,
) -> Result<DecryptionStream<F>>
where
    F: Fn(&[(usize, XorName)]) -> Result<Vec<(usize, Bytes)>>,
{
    DecryptionStream::new_with_batch_size(data_map, get_chunk_parallel, batch_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt, test_helpers::random_bytes, Error};
    use std::collections::HashMap;

    /// Enough content for the minimum of three chunks.
    const SMALL_FILE_BYTES: usize = 10_000;

    #[test]
    fn test_streaming_decrypt_basic() -> Result<()> {
        // Create test data
        let original_data = random_bytes(50_000); // Small test file
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        // Create storage map
        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        // Create chunk retrieval function
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Test streaming decryption
        let stream = streaming_decrypt(&data_map, get_chunks)?;
        let mut decrypted_data = Vec::new();

        for chunk_result in stream {
            let chunk = chunk_result?;
            decrypted_data.extend_from_slice(&chunk);
        }

        assert_eq!(decrypted_data, original_data.to_vec());
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_large_file() -> Result<()> {
        // Create larger test data
        let original_data = random_bytes(5_000_000); // 5MB test file
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        // Create storage map
        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        // Create chunk retrieval function
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Test streaming decryption with different batch sizes
        let stream = streaming_decrypt(&data_map, get_chunks)?;
        let mut decrypted_data = Vec::new();
        let mut chunk_count = 0;

        for chunk_result in stream {
            let chunk = chunk_result?;
            decrypted_data.extend_from_slice(&chunk);
            chunk_count += 1;
        }

        assert_eq!(decrypted_data, original_data.to_vec());
        assert!(chunk_count > 1, "Should have processed multiple chunks");
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_explicit_batch_size() -> Result<()> {
        let original_data = random_bytes(9_000_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let observed_batch_sizes = std::cell::RefCell::new(Vec::new());
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            observed_batch_sizes.borrow_mut().push(hashes.len());
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt_with_batch_size(&data_map, get_chunks, 2)?;
        let mut decrypted_data = Vec::new();
        for chunk_result in stream {
            let chunk = chunk_result?;
            decrypted_data.extend_from_slice(&chunk);
        }

        assert_eq!(decrypted_data, original_data.to_vec());
        let observed = observed_batch_sizes.borrow();
        assert!(
            observed.len() >= 2,
            "expected multiple fetch batches, got {:?}",
            observed
        );
        assert!(
            observed.iter().all(|size| *size <= 2),
            "all batches should respect explicit size, got {:?}",
            observed
        );
        Ok(())
    }

    #[test]
    fn test_random_access_respects_explicit_batch_size() -> Result<()> {
        let original_data = random_bytes(9_000_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let observed_batch_sizes = std::cell::RefCell::new(Vec::new());
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            observed_batch_sizes.borrow_mut().push(hashes.len());
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt_with_batch_size(&data_map, get_chunks, 2)?;
        let decrypted_data = stream.range_full()?;

        assert_eq!(decrypted_data, original_data);
        let observed = observed_batch_sizes.borrow();
        assert!(
            observed.len() >= 2,
            "expected multiple range fetch batches, got {:?}",
            observed
        );
        assert!(
            observed.iter().all(|size| *size <= 2),
            "range fetches should respect explicit size, got {:?}",
            observed
        );
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_explicit_batch_size_rejects_zero() -> Result<()> {
        let original_data = random_bytes(50_000);
        let (data_map, _encrypted_chunks) = encrypt(original_data)?;
        let get_chunks =
            |_hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> { Ok(Vec::new()) };

        let err = match streaming_decrypt_with_batch_size(&data_map, get_chunks, 0) {
            Ok(_) => panic!("zero batch size should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("> 0"), "got: {}", err);
        Ok(())
    }

    #[test]
    fn test_streaming_decrypt_error_handling() -> Result<()> {
        // Create test data
        let original_data = random_bytes(10_000);
        let (data_map, encrypted_chunks) = encrypt(original_data)?;

        // Create incomplete storage (missing some chunks)
        let mut storage = HashMap::new();
        for (i, chunk) in encrypted_chunks.iter().enumerate() {
            if i < encrypted_chunks.len() - 1 {
                // Skip the last chunk to simulate missing data
                let hash = crate::hash::content_hash(&chunk.content);
                let _ = storage.insert(hash, chunk.content.to_vec());
            }
        }

        // Create chunk retrieval function that will fail on missing chunks
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        // Test that streaming properly handles errors
        let stream = streaming_decrypt(&data_map, get_chunks)?;
        let mut found_error = false;

        for chunk_result in stream {
            match chunk_result {
                Ok(_chunk) => {
                    // Continue processing successful chunks
                }
                Err(_e) => {
                    found_error = true;
                    break;
                }
            }
        }

        assert!(
            found_error,
            "Should have encountered an error for missing chunk"
        );
        Ok(())
    }

    #[test]
    fn test_omitted_chunk_fails_instead_of_truncating() -> Result<()> {
        let (data_map, encrypted_chunks) = encrypt(random_bytes(SMALL_FILE_BYTES))?;
        let storage: HashMap<XorName, Bytes> = encrypted_chunks
            .into_iter()
            .map(|chunk| (crate::hash::content_hash(&chunk.content), chunk.content))
            .collect();
        let last_chunk = data_map.len() - 1;

        // Succeeds while silently leaving out the last chunk
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            Ok(hashes
                .iter()
                .filter(|(index, _)| *index != last_chunk)
                .map(|(index, hash)| (*index, storage[hash].clone()))
                .collect())
        };
        let mut stream = streaming_decrypt(&data_map, get_chunks)?;

        assert!(stream.range_full().is_err());
        assert!(
            stream.any(|chunk| chunk.is_err()),
            "iteration must fail rather than end early"
        );
        Ok(())
    }

    #[test]
    fn test_random_access_basic() -> Result<()> {
        // Create test data
        let original_data = random_bytes(10_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        // Create storage map
        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        // Create chunk retrieval function
        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                } else {
                    return Err(Error::Generic(format!(
                        "Chunk not found: {}",
                        hex::encode(hash)
                    )));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;

        // Test basic range access
        let range_start = 1000;
        let range_len = 500;
        let range_data = stream.get_range(range_start, range_len)?;

        // Verify against original data
        assert_eq!(range_data.len(), range_len);
        assert_eq!(
            range_data.as_ref(),
            &original_data[range_start..range_start + range_len]
        );

        Ok(())
    }

    #[test]
    fn test_random_access_convenience_methods() -> Result<()> {
        let original_data = random_bytes(5_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;

        // Test range method
        let range_data = stream.range(1000..2000)?;
        assert_eq!(range_data.as_ref(), &original_data[1000..2000]);

        // Test range_from method
        let from_data = stream.range_from(3000)?;
        assert_eq!(from_data.as_ref(), &original_data[3000..]);

        // Test range_to method
        let to_data = stream.range_to(1500)?;
        assert_eq!(to_data.as_ref(), &original_data[..1500]);

        // Test range_full method
        let full_data = stream.range_full()?;
        assert_eq!(full_data.as_ref(), &original_data[..]);

        // Test range_inclusive method
        let inclusive_data = stream.range_inclusive(500, 999)?;
        assert_eq!(inclusive_data.as_ref(), &original_data[500..1000]); // 500 to 999 inclusive = 500..1000

        Ok(())
    }

    #[test]
    fn test_random_access_edge_cases() -> Result<()> {
        let original_data = random_bytes(1_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;

        // Test range beyond file size
        let beyond_range = stream.get_range(2000, 500)?;
        assert_eq!(beyond_range.len(), 0);

        // Test range starting at file size
        let at_end = stream.get_range(1000, 100)?;
        assert_eq!(at_end.len(), 0);

        // Test range that partially exceeds file size
        let partial_exceed = stream.get_range(950, 100)?;
        assert_eq!(partial_exceed.len(), 50); // Only 50 bytes available from position 950
        assert_eq!(partial_exceed.as_ref(), &original_data[950..]);

        // Test zero-length range
        let zero_len = stream.get_range(500, 0)?;
        assert_eq!(zero_len.len(), 0);

        // Test range at start of file
        let at_start = stream.get_range(0, 100)?;
        assert_eq!(at_start.as_ref(), &original_data[0..100]);

        Ok(())
    }

    #[test]
    fn test_random_access_chunk_boundaries() -> Result<()> {
        // Create data large enough to span multiple chunks
        let original_data = random_bytes(5_000_000); // 5MB to ensure multiple chunks
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;

        // Test ranges that cross chunk boundaries
        let cross_boundary = stream.get_range(1_000_000, 2_000_000)?; // Should span multiple chunks
        assert_eq!(cross_boundary.len(), 2_000_000);
        assert_eq!(
            cross_boundary.as_ref(),
            &original_data[1_000_000..3_000_000]
        );

        // Test small ranges within single chunks
        let within_chunk = stream.get_range(500_000, 1000)?;
        assert_eq!(within_chunk.len(), 1000);
        assert_eq!(within_chunk.as_ref(), &original_data[500_000..501_000]);

        Ok(())
    }

    #[test]
    fn test_random_access_file_size() -> Result<()> {
        let original_data = random_bytes(1234); // Odd size
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        let stream = streaming_decrypt(&data_map, get_chunks)?;

        // Test file_size method
        assert_eq!(stream.file_size(), 1234);

        // Test getting exactly the full file
        let full_file = stream.get_range(0, 1234)?;
        assert_eq!(full_file.len(), 1234);
        assert_eq!(full_file.as_ref(), &original_data[..]);

        Ok(())
    }

    #[test]
    fn test_random_access_vs_sequential() -> Result<()> {
        // Test that random access produces the same results as sequential reading
        let original_data = random_bytes(100_000);
        let (data_map, encrypted_chunks) = encrypt(original_data.clone())?;

        let mut storage = HashMap::new();
        for chunk in encrypted_chunks {
            let hash = crate::hash::content_hash(&chunk.content);
            let _ = storage.insert(hash, chunk.content.to_vec());
        }

        let get_chunks = |hashes: &[(usize, XorName)]| -> Result<Vec<(usize, Bytes)>> {
            let mut results = Vec::new();
            for &(index, hash) in hashes {
                if let Some(data) = storage.get(&hash) {
                    results.push((index, Bytes::from(data.clone())));
                }
            }
            Ok(results)
        };

        // Get data via random access
        let stream = streaming_decrypt(&data_map, &get_chunks)?;
        let random_access_data = stream.range_full()?;

        // Get data via sequential iteration
        let stream2 = streaming_decrypt(&data_map, get_chunks)?;
        let mut sequential_data = Vec::new();
        for chunk_result in stream2 {
            sequential_data.extend_from_slice(&chunk_result?);
        }

        // Both should match the original
        assert_eq!(random_access_data.as_ref(), &original_data[..]);
        assert_eq!(sequential_data, original_data.to_vec());
        assert_eq!(random_access_data.as_ref(), &sequential_data[..]);

        Ok(())
    }
}
