// Copyright 2026 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

//! Random access to the content of a `DataMap` with 64-bit positions.

use crate::{
    decrypt::decrypt_chunk_bounded, hash::content_hash, ChunkInfo, DataMap, Error, Result,
};
use bytes::Bytes;
use std::ops::Range;
use xor_name::XorName;

/// Random access to the content of a [`DataMap`], with 64-bit positions on
/// every platform.
///
/// The index performs no I/O. Callers fetch the encrypted chunks listed by
/// [`Self::infos`] however suits them, for example concurrently and
/// asynchronously, and pass each one to [`Self::decrypt_chunk`]. Positions are
/// `u64`, so content larger than `usize::MAX` bytes stays addressable on
/// 32-bit targets such as `wasm32`.
///
/// The content of a shrunk (child) map is its serialized parent map. Resolve
/// it with [`crate::get_root_data_map`] first to index the original data.
///
/// # Example
///
/// ```rust
/// use self_encryption::{encrypt, test_helpers::random_bytes, DataMapIndex};
///
/// # fn main() -> self_encryption::Result<()> {
/// let original = random_bytes(10_000);
/// let (data_map, chunks) = encrypt(original.clone())?;
/// let index = DataMapIndex::new(&data_map)?;
///
/// // Decrypt only the chunks holding bytes 4000..6000.
/// let (start, end) = (4000u64, 6000u64);
/// let mut range = Vec::new();
/// for chunk in index.chunks_overlapping(start..end) {
///     // Here the chunks come straight from `encrypt`, in index order. A real
///     // caller fetches `index.infos()[chunk].dst_hash` from storage.
///     let plaintext = index.decrypt_chunk(chunk, &chunks[chunk].content)?;
///     let span = index.chunk_range(chunk);
///     let from = (start.max(span.start) - span.start) as usize;
///     let to = (end.min(span.end) - span.start) as usize;
///     range.extend_from_slice(&plaintext[from..to]);
/// }
/// assert_eq!(&range[..], &original[4000..6000]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct DataMapIndex {
    /// The map's chunks, where `infos[i].index == i`.
    infos: Vec<ChunkInfo>,
    /// Pre-encryption hashes in chunk order. Every chunk's keys derive from
    /// its own and its neighbours' hashes.
    src_hashes: Vec<XorName>,
    /// Content offset of each chunk, followed by the content size.
    offsets: Vec<u64>,
    /// Key-derivation level the map's chunks were encrypted at.
    child_level: usize,
}

impl DataMapIndex {
    /// Index the chunks of `data_map`.
    ///
    /// # Errors
    ///
    /// Fails if the chunk indices are not exactly `0..n`, or if the content
    /// size overflows `u64`.
    pub fn new(data_map: &DataMap) -> Result<Self> {
        let mut infos = data_map.infos().to_vec();
        infos.sort_by_key(|info| info.index);
        let mut offsets = Vec::with_capacity(infos.len() + 1);
        let mut end = 0u64;
        offsets.push(end);
        for (position, info) in infos.iter().enumerate() {
            if info.index != position {
                return Err(Error::Generic(format!(
                    "DataMap chunk indices must be contiguous from 0; found {} at position {position}",
                    info.index
                )));
            }
            end = end
                .checked_add(info.src_size as u64)
                .ok_or_else(|| Error::Generic("DataMap content size overflows u64".to_string()))?;
            offsets.push(end);
        }
        Ok(Self {
            src_hashes: infos.iter().map(|info| info.src_hash).collect(),
            infos,
            offsets,
            child_level: data_map.child().unwrap_or(0),
        })
    }

    /// Size of the content in bytes.
    pub fn file_size(&self) -> u64 {
        self.offsets.last().copied().unwrap_or_default()
    }

    /// The map's chunks in index order: `infos()[i].index == i`.
    pub fn infos(&self) -> &[ChunkInfo] {
        &self.infos
    }

    /// Half-open byte range of the content held by chunk `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not below `infos().len()`.
    pub fn chunk_range(&self, index: usize) -> Range<u64> {
        self.offsets[index]..self.offsets[index + 1]
    }

    /// Indices of the chunks overlapping the half-open byte range `range`,
    /// which is clamped at the end of the content. Empty when nothing of the
    /// content lies inside `range`.
    pub fn chunks_overlapping(&self, range: Range<u64>) -> Range<usize> {
        let end = range.end.min(self.file_size());
        if range.start >= end {
            return 0..0;
        }
        // `offsets[0]` is 0, so at least one offset is at or before the start.
        let first = self
            .offsets
            .partition_point(|offset| *offset <= range.start)
            - 1;
        let last = self.offsets.partition_point(|offset| *offset < end);
        first..last
    }

    /// Decrypt chunk `index` from its encrypted `content`, checking that the
    /// result has the size and hash the map declares.
    ///
    /// Decompression stops at the declared size, so crafted content cannot
    /// expand beyond what the map states.
    ///
    /// # Errors
    ///
    /// Fails if `index` is out of range, if `content` does not decrypt with
    /// the chunk's keys, or if the result differs from the declared size or
    /// hash.
    pub fn decrypt_chunk(&self, index: usize, content: &Bytes) -> Result<Bytes> {
        let info = self.infos.get(index).ok_or_else(|| {
            Error::Generic(format!(
                "chunk index {index} out of bounds for {} chunks",
                self.infos.len()
            ))
        })?;
        let plaintext = decrypt_chunk_bounded(
            index,
            content,
            &self.src_hashes,
            self.child_level,
            info.src_size,
        )?;
        if plaintext.len() != info.src_size {
            return Err(Error::Generic(format!(
                "chunk {index} decrypted to {} bytes, but the DataMap declares {}",
                plaintext.len(),
                info.src_size
            )));
        }
        if content_hash(&plaintext) != info.src_hash {
            return Err(Error::Generic(format!(
                "chunk {index} does not match its DataMap source hash"
            )));
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Content of a small map: three chunks, the fewest `encrypt` produces.
    const SMALL_CONTENT_BYTES: usize = 10_000;
    /// Chunk size for indexes larger than 32-bit `usize` can address.
    const LARGE_CHUNK_BYTES: usize = 1 << 30;
    /// Chunks in the large index: 6 GiB of content.
    const LARGE_CHUNKS: usize = 6;
    /// Offset that 32-bit `usize` arithmetic cannot represent.
    const FOUR_GIB: u64 = 1 << 32;

    fn small_map() -> Result<(Bytes, DataMap, Vec<Bytes>)> {
        let content = crate::test_helpers::random_bytes(SMALL_CONTENT_BYTES);
        let (map, chunks) = crate::encrypt(content.clone())?;
        let mut by_index = vec![Bytes::new(); map.len()];
        for info in map.infos() {
            by_index[info.index] = chunks
                .iter()
                .find(|chunk| content_hash(&chunk.content) == info.dst_hash)
                .map(|chunk| chunk.content.clone())
                .expect("encrypt returns every chunk of its map");
        }
        Ok((content, map, by_index))
    }

    fn large_map() -> DataMap {
        DataMap::new(
            (0..LARGE_CHUNKS)
                .map(|index| ChunkInfo {
                    index,
                    dst_hash: content_hash(&index.to_le_bytes()),
                    src_hash: content_hash(&index.to_be_bytes()),
                    src_size: LARGE_CHUNK_BYTES,
                })
                .collect(),
        )
    }

    #[test]
    fn decrypted_chunks_reassemble_the_content() -> Result<()> {
        let (content, map, chunks) = small_map()?;
        let index = DataMapIndex::new(&map)?;
        assert_eq!(index.file_size(), content.len() as u64);
        let mut reassembled = Vec::new();
        for (chunk, encrypted) in chunks.iter().enumerate() {
            let plaintext = index.decrypt_chunk(chunk, encrypted)?;
            assert_eq!(plaintext.len() as u64, {
                let span = index.chunk_range(chunk);
                span.end - span.start
            });
            reassembled.extend_from_slice(&plaintext);
        }
        assert_eq!(reassembled, content.to_vec());
        Ok(())
    }

    #[test]
    fn overlapping_chunks_follow_half_open_ranges() -> Result<()> {
        let (content, map, _) = small_map()?;
        let index = DataMapIndex::new(&map)?;
        let size = content.len() as u64;
        let boundary = index.chunk_range(1).start;
        assert_eq!(index.chunks_overlapping(0..1), 0..1);
        assert_eq!(index.chunks_overlapping(boundary - 1..boundary), 0..1);
        assert_eq!(index.chunks_overlapping(boundary - 1..boundary + 1), 0..2);
        assert_eq!(index.chunks_overlapping(boundary..boundary + 1), 1..2);
        assert_eq!(index.chunks_overlapping(0..u64::MAX), 0..3);
        assert_eq!(index.chunks_overlapping(size - 1..u64::MAX), 2..3);
        assert_eq!(index.chunks_overlapping(size..size + 1), 0..0);
        assert_eq!(index.chunks_overlapping(5..5), 0..0);
        Ok(())
    }

    #[test]
    fn positions_beyond_four_gib_need_no_wide_usize() -> Result<()> {
        let index = DataMapIndex::new(&large_map())?;
        let chunk_bytes = LARGE_CHUNK_BYTES as u64;
        assert_eq!(index.file_size(), LARGE_CHUNKS as u64 * chunk_bytes);
        let at_four_gib = (FOUR_GIB / chunk_bytes) as usize;
        assert_eq!(
            index.chunks_overlapping(FOUR_GIB - 1..FOUR_GIB + 1),
            at_four_gib - 1..at_four_gib + 1
        );
        let last = LARGE_CHUNKS - 1;
        let end = index.file_size();
        assert_eq!(index.chunk_range(last), end - chunk_bytes..end);
        assert_eq!(index.chunks_overlapping(end - 1..end), last..LARGE_CHUNKS);
        Ok(())
    }

    #[test]
    fn positions_map_by_the_maps_own_chunk_sizes() -> Result<()> {
        // Reported underflow: a ~15.27 GB file chunked with twice this build's
        // MAX_CHUNK_SIZE, read from 4 MiB.
        let file_size = 16_404_310_194u64 as usize;
        let start = 4_194_304u64;
        let max_chunk_size = crate::MAX_CHUNK_SIZE * 2;
        let chunks = crate::utils::get_num_chunks_with_variable_max(file_size, max_chunk_size);
        let map = DataMap::new(
            (0..chunks)
                .map(|index| ChunkInfo {
                    index,
                    src_size: crate::utils::get_chunk_size_with_variable_max(
                        file_size,
                        index,
                        max_chunk_size,
                    ),
                    ..ChunkInfo::default()
                })
                .collect(),
        );
        let index = DataMapIndex::new(&map)?;
        assert_eq!(index.file_size(), file_size as u64);
        let chunk = index.chunks_overlapping(start..start + 1).start;
        assert!(index.chunk_range(chunk).contains(&start));
        Ok(())
    }

    #[test]
    fn indices_must_run_from_zero_without_gaps_or_repeats() {
        for indices in [[0, 1, 3], [0, 0, 1], [1, 2, 3]] {
            let map = DataMap::new(
                indices
                    .iter()
                    .map(|&index| ChunkInfo {
                        index,
                        src_size: 1,
                        ..ChunkInfo::default()
                    })
                    .collect(),
            );
            assert!(DataMapIndex::new(&map).is_err(), "accepted {:?}", indices);
        }
    }

    #[test]
    fn content_must_have_the_declared_size() -> Result<()> {
        let (_, map, chunks) = small_map()?;
        for delta in [-1isize, 1] {
            let mut infos = map.infos().to_vec();
            infos[0].src_size = (infos[0].src_size as isize + delta) as usize;
            let index = DataMapIndex::new(&DataMap::new(infos))?;
            assert!(
                index.decrypt_chunk(0, &chunks[0]).is_err(),
                "size delta {}",
                delta
            );
        }
        Ok(())
    }

    #[test]
    fn content_must_have_the_declared_hash() -> Result<()> {
        let (content, map, _) = small_map()?;
        // A crafted map whose first chunk declares the wrong source hash, with
        // every chunk encrypted under keys derived from the declared hashes.
        let mut infos = map.infos().to_vec();
        infos[0].src_hash = content_hash(b"not the first chunk");
        let src_hashes: Vec<_> = infos.iter().map(|info| info.src_hash).collect();
        let index = DataMapIndex::new(&DataMap::new(infos))?;
        let span = index.chunk_range(0);
        let plaintext = content.slice(span.start as usize..span.end as usize);
        let keys = crate::utils::get_pad_key_and_nonce(0, &src_hashes, 0)?;
        let encrypted = crate::encrypt::encrypt_chunk(plaintext, keys)?;
        assert!(index.decrypt_chunk(0, &encrypted).is_err());
        Ok(())
    }

    #[test]
    fn chunk_index_must_be_in_range() -> Result<()> {
        let (_, map, chunks) = small_map()?;
        let index = DataMapIndex::new(&map)?;
        assert!(index.decrypt_chunk(chunks.len(), &chunks[0]).is_err());
        Ok(())
    }
}
