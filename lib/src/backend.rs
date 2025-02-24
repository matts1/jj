// Copyright 2020 The Jujutsu Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(missing_docs)]

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Read;
use std::result::Result;
use std::vec::Vec;

use async_trait::async_trait;
use thiserror::Error;

use crate::content_hash::ContentHash;
use crate::merge::Merge;
use crate::repo_path::{RepoPath, RepoPathComponent};

pub trait ObjectId {
    fn new(value: Vec<u8>) -> Self;
    fn object_type(&self) -> String;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn as_bytes(&self) -> &[u8];
    fn to_bytes(&self) -> Vec<u8>;
    fn from_hex(hex: &str) -> Self;
    fn hex(&self) -> String;
}

macro_rules! id_type {
    ($vis:vis $name:ident) => {
        content_hash! {
            #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
            $vis struct $name(Vec<u8>);
        }
        $crate::backend::impl_id_type!($name);
    };
}

macro_rules! impl_id_type {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                f.debug_tuple(stringify!($name)).field(&self.hex()).finish()
            }
        }

        impl crate::backend::ObjectId for $name {
            fn new(value: Vec<u8>) -> Self {
                Self(value)
            }

            fn object_type(&self) -> String {
                stringify!($name)
                    .strip_suffix("Id")
                    .unwrap()
                    .to_ascii_lowercase()
                    .to_string()
            }

            fn from_bytes(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }

            fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            fn to_bytes(&self) -> Vec<u8> {
                self.0.clone()
            }

            fn from_hex(hex: &str) -> Self {
                Self(hex::decode(hex).unwrap())
            }

            fn hex(&self) -> String {
                hex::encode(&self.0)
            }
        }
    };
}

pub(crate) use {id_type, impl_id_type};

id_type!(pub CommitId);
id_type!(pub ChangeId);
id_type!(pub TreeId);
id_type!(pub FileId);
id_type!(pub SymlinkId);
id_type!(pub ConflictId);

content_hash! {
    #[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
    pub struct MillisSinceEpoch(pub i64);
}

content_hash! {
    #[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
    pub struct Timestamp {
        pub timestamp: MillisSinceEpoch,
        // time zone offset in minutes
        pub tz_offset: i32,
    }
}

impl Timestamp {
    pub fn now() -> Self {
        Self::from_datetime(chrono::offset::Local::now())
    }

    pub fn from_datetime<Tz: chrono::TimeZone<Offset = chrono::offset::FixedOffset>>(
        datetime: chrono::DateTime<Tz>,
    ) -> Self {
        Self {
            timestamp: MillisSinceEpoch(datetime.timestamp_millis()),
            tz_offset: datetime.offset().local_minus_utc() / 60,
        }
    }
}

content_hash! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Signature {
        pub name: String,
        pub email: String,
        pub timestamp: Timestamp,
    }
}

content_hash! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct SecureSig {
        pub data: Vec<u8>,
        pub sig: Vec<u8>,
    }
}

/// Identifies a single legacy tree, which may have path-level conflicts, or a
/// merge of multiple trees, where the individual trees do not have conflicts.
// TODO(#1624): Delete this type at some point in the future, when we decide to drop
// support for conflicts in older repos, or maybe after we have provided an upgrade
// mechanism.
#[derive(Debug, Clone)]
pub enum MergedTreeId {
    /// The tree id of a legacy tree
    Legacy(TreeId),
    /// The tree id(s) of a merge tree
    Merge(Merge<TreeId>),
}

impl PartialEq for MergedTreeId {
    /// Overridden to make conflict-free trees be considered equal even if their
    /// `MergedTreeId` variant is different.
    fn eq(&self, other: &Self) -> bool {
        self.to_merge() == other.to_merge()
    }
}

impl Eq for MergedTreeId {}

impl ContentHash for MergedTreeId {
    fn hash(&self, state: &mut impl digest::Update) {
        match self {
            MergedTreeId::Legacy(tree_id) => {
                state.update(b"0");
                ContentHash::hash(tree_id, state);
            }
            MergedTreeId::Merge(tree_ids) => {
                state.update(b"1");
                ContentHash::hash(tree_ids, state);
            }
        }
    }
}

impl MergedTreeId {
    /// Create a resolved `MergedTreeId` from a single regular tree.
    pub fn resolved(tree_id: TreeId) -> Self {
        MergedTreeId::Merge(Merge::resolved(tree_id))
    }

    /// Return this id as `Merge<TreeId>`
    pub fn to_merge(&self) -> Merge<TreeId> {
        match self {
            MergedTreeId::Legacy(tree_id) => Merge::resolved(tree_id.clone()),
            MergedTreeId::Merge(tree_ids) => tree_ids.clone(),
        }
    }
}

content_hash! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Commit {
        pub parents: Vec<CommitId>,
        pub predecessors: Vec<CommitId>,
        pub root_tree: MergedTreeId,
        pub change_id: ChangeId,
        pub description: String,
        pub author: Signature,
        pub committer: Signature,
        pub secure_sig: Option<SecureSig>,
    }
}

content_hash! {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct ConflictTerm {
        pub value: TreeValue,
    }
}

content_hash! {
    #[derive(Default, Debug, PartialEq, Eq, Clone)]
    pub struct Conflict {
        // A conflict is represented by a list of positive and negative states that need to be applied.
        // In a simple 3-way merge of B and C with merge base A, the conflict will be { add: [B, C],
        // remove: [A] }. Also note that a conflict of the form { add: [A], remove: [] } is the
        // same as non-conflict A.
        pub removes: Vec<ConflictTerm>,
        pub adds: Vec<ConflictTerm>,
    }
}

/// Error that may occur during backend initialization.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct BackendInitError(pub Box<dyn std::error::Error + Send + Sync>);

/// Error that may occur during backend loading.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct BackendLoadError(pub Box<dyn std::error::Error + Send + Sync>);

/// Commit-backend error that may occur after the backend is loaded.
#[derive(Debug, Error)]
pub enum BackendError {
    #[error(
        "Invalid hash length for object of type {object_type} (expected {expected} bytes, got \
         {actual} bytes): {hash}"
    )]
    InvalidHashLength {
        expected: usize,
        actual: usize,
        object_type: String,
        hash: String,
    },
    #[error("Invalid UTF-8 for object {hash} of type {object_type}: {source}")]
    InvalidUtf8 {
        object_type: String,
        hash: String,
        source: std::str::Utf8Error,
    },
    #[error("Object {hash} of type {object_type} not found: {source}")]
    ObjectNotFound {
        object_type: String,
        hash: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Error when reading object {hash} of type {object_type}: {source}")]
    ReadObject {
        object_type: String,
        hash: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Could not write object of type {object_type}: {source}")]
    WriteObject {
        object_type: &'static str,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

pub type BackendResult<T> = Result<T, BackendError>;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum TreeValue {
    File { id: FileId, executable: bool },
    Symlink(SymlinkId),
    Tree(TreeId),
    GitSubmodule(CommitId),
    Conflict(ConflictId),
}

impl TreeValue {
    pub fn hex(&self) -> String {
        match self {
            TreeValue::File { id, .. } => id.hex(),
            TreeValue::Symlink(id) => id.hex(),
            TreeValue::Tree(id) => id.hex(),
            TreeValue::GitSubmodule(id) => id.hex(),
            TreeValue::Conflict(id) => id.hex(),
        }
    }
}

impl ContentHash for TreeValue {
    fn hash(&self, state: &mut impl digest::Update) {
        use TreeValue::*;
        match self {
            File { id, executable } => {
                state.update(&0u32.to_le_bytes());
                id.hash(state);
                executable.hash(state);
            }
            Symlink(id) => {
                state.update(&1u32.to_le_bytes());
                id.hash(state);
            }
            Tree(id) => {
                state.update(&2u32.to_le_bytes());
                id.hash(state);
            }
            GitSubmodule(id) => {
                state.update(&3u32.to_le_bytes());
                id.hash(state);
            }
            Conflict(id) => {
                state.update(&4u32.to_le_bytes());
                id.hash(state);
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TreeEntry<'a> {
    name: &'a RepoPathComponent,
    value: &'a TreeValue,
}

impl<'a> TreeEntry<'a> {
    pub fn new(name: &'a RepoPathComponent, value: &'a TreeValue) -> Self {
        TreeEntry { name, value }
    }

    pub fn name(&self) -> &'a RepoPathComponent {
        self.name
    }

    pub fn value(&self) -> &'a TreeValue {
        self.value
    }
}

pub struct TreeEntriesNonRecursiveIterator<'a> {
    iter: std::collections::btree_map::Iter<'a, RepoPathComponent, TreeValue>,
}

impl<'a> Iterator for TreeEntriesNonRecursiveIterator<'a> {
    type Item = TreeEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(name, value)| TreeEntry { name, value })
    }
}

content_hash! {
    #[derive(Default, PartialEq, Eq, Debug, Clone)]
    pub struct Tree {
        entries: BTreeMap<RepoPathComponent, TreeValue>,
    }
}

impl Tree {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &RepoPathComponent> {
        self.entries.keys()
    }

    pub fn entries(&self) -> TreeEntriesNonRecursiveIterator {
        TreeEntriesNonRecursiveIterator {
            iter: self.entries.iter(),
        }
    }

    pub fn set(&mut self, name: RepoPathComponent, value: TreeValue) {
        self.entries.insert(name, value);
    }

    pub fn remove(&mut self, name: &RepoPathComponent) {
        self.entries.remove(name);
    }

    pub fn set_or_remove(&mut self, name: &RepoPathComponent, value: Option<TreeValue>) {
        match value {
            None => {
                self.entries.remove(name);
            }
            Some(value) => {
                self.entries.insert(name.clone(), value);
            }
        }
    }

    pub fn entry(&self, name: &RepoPathComponent) -> Option<TreeEntry> {
        self.entries
            .get_key_value(name)
            .map(|(name, value)| TreeEntry { name, value })
    }

    pub fn value(&self, name: &RepoPathComponent) -> Option<&TreeValue> {
        self.entries.get(name)
    }
}

/// Calculates common prefix length of two bytes. The length to be returned is
/// a number of hexadecimal digits.
pub fn common_hex_len(bytes_a: &[u8], bytes_b: &[u8]) -> usize {
    iter_half_bytes(bytes_a)
        .zip(iter_half_bytes(bytes_b))
        .take_while(|(a, b)| a == b)
        .count()
}

fn iter_half_bytes(bytes: &[u8]) -> impl ExactSizeIterator<Item = u8> + '_ {
    (0..bytes.len() * 2).map(|i| {
        let v = bytes[i / 2];
        if i & 1 == 0 {
            v >> 4
        } else {
            v & 0xf
        }
    })
}

pub fn make_root_commit(root_change_id: ChangeId, empty_tree_id: TreeId) -> Commit {
    let timestamp = Timestamp {
        timestamp: MillisSinceEpoch(0),
        tz_offset: 0,
    };
    let signature = Signature {
        name: String::new(),
        email: String::new(),
        timestamp,
    };
    Commit {
        parents: vec![],
        predecessors: vec![],
        root_tree: MergedTreeId::Legacy(empty_tree_id),
        change_id: root_change_id,
        description: String::new(),
        author: signature.clone(),
        committer: signature,
        secure_sig: None,
    }
}

#[async_trait]
pub trait Backend: Send + Sync + Debug {
    fn as_any(&self) -> &dyn Any;

    /// A unique name that identifies this backend. Written to
    /// `.jj/repo/store/backend` when the repo is created.
    fn name(&self) -> &str;

    /// The length of commit IDs in bytes.
    fn commit_id_length(&self) -> usize;

    /// The length of change IDs in bytes.
    fn change_id_length(&self) -> usize;

    fn root_commit_id(&self) -> &CommitId;

    fn root_change_id(&self) -> &ChangeId;

    fn empty_tree_id(&self) -> &TreeId;

    /// An estimate of how many concurrent requests this backend handles well. A
    /// local backend like the Git backend (at until it supports partial clones)
    /// may want to set this to 1. A cloud-backed backend may want to set it to
    /// 100 or so.
    ///
    /// It is not guaranteed that at most this number of concurrent requests are
    /// sent.
    fn concurrency(&self) -> usize;

    async fn read_file(&self, path: &RepoPath, id: &FileId) -> BackendResult<Box<dyn Read>>;

    fn write_file(&self, path: &RepoPath, contents: &mut dyn Read) -> BackendResult<FileId>;

    async fn read_symlink(&self, path: &RepoPath, id: &SymlinkId) -> BackendResult<String>;

    fn write_symlink(&self, path: &RepoPath, target: &str) -> BackendResult<SymlinkId>;

    async fn read_tree(&self, path: &RepoPath, id: &TreeId) -> BackendResult<Tree>;

    fn write_tree(&self, path: &RepoPath, contents: &Tree) -> BackendResult<TreeId>;

    // Not async because it would force `MergedTree::value()` to be async. We don't
    // need this to be async anyway because it's only used by legacy repos.
    fn read_conflict(&self, path: &RepoPath, id: &ConflictId) -> BackendResult<Conflict>;

    fn write_conflict(&self, path: &RepoPath, contents: &Conflict) -> BackendResult<ConflictId>;

    async fn read_commit(&self, id: &CommitId) -> BackendResult<Commit>;

    /// Writes a commit and returns its ID and the commit itself. The commit
    /// should contain the data that was actually written, which may differ
    /// from the data passed in. For example, the backend may change the
    /// committer name to an authenticated user's name, or the backend's
    /// timestamps may have less precision than the millisecond precision in
    /// `Commit`.
    fn write_commit(&self, contents: Commit) -> BackendResult<(CommitId, Commit)>;
}
