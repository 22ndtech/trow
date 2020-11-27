
use serde::{Deserialize, Serialize};
use crate::registry_interface::{digest, StorageDriverError};
use std::time::SystemTime;

/// This is the Internal TAG representation
#[derive(Serialize, Deserialize, Debug, Clone, PartialOrd, Eq, PartialEq)]
pub struct TagEntry {

    /// This is the tag name
    pub name: String,

    /// This is the digest value
    pub digest: String,

    /// Signature of the whole image/artifact TAG
    pub signature: String,

    /// The size of the whole image
    pub size: u64,

    /// When the tag was pushed
    pub pushed_at: u128,

    /// Indicates last time this TAG was scanned for vulnerabilities
    pub last_vulnerability_scan: usize,

    /// Total amount of severe vulnerabilities
    pub severe_vulnerabilities: usize,

    /// Total amount of medium vulnerabilities
    pub medium_vulnerabilities: usize,

    /// Total amount of low vulnerabilities
    pub low_vulnerabilities: usize,

}

impl TagEntry {
    pub fn new(name: &str, digest: &str, size: u64) -> TagEntry {

        let pushed_at = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_nanos(),
            Err(_) => 0u128,
        };

        TagEntry {
            name: name.to_string(),
            digest: digest.to_string(),
            signature: "".to_string(),
            size,
            pushed_at,
            last_vulnerability_scan: 0,
            severe_vulnerabilities: 0,
            medium_vulnerabilities: 0,
            low_vulnerabilities: 0
        }
    }
}

/// Holds Metadata information and the tags
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TagEntries {
    /// TAG Entries
    entries: Vec<TagEntry>,
}

impl TagEntries {

    /// new instance
    pub fn new() -> TagEntries {
        return TagEntries {
            entries: vec![]
        }
    }

    /// new instance
    pub fn all_digest(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.digest.to_string()).collect()
    }

    /// new instance
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total namespace size
    pub fn tags_size(&self) -> u64 {

        // if we cannot get the read lock, then we can return 0
        if self.entries.is_empty() {
            return 0;
        }

        let mut total: u64 = 0;
        for tag in self.entries.iter() {
            total += tag.size;
        }

        total
    }

    pub fn entries(&self) -> Vec<TagEntry> {
        self.entries.clone()
    }

    /// Delete a specific entry by its digest
    pub fn delete_by_digest(&mut self, digest: &str) {
        let index = self.entries.iter().position(|e| e.digest == digest).unwrap();
        self.entries.remove(index);
    }

    /// Get the latest entry (since it's a vector is the last pushed entry)
    /// or None if the vector is empty.
    /// The TagEntries contain an array of different version of tags so this method helps finding the
    /// most up to date version of the tag
    pub fn latest(&self) -> Option<TagEntry> {
        let total = self.entries.len();
        if total == 0 {
            None
        } else {
            Some(self.entries[total-1].clone())
        }
    }

    /// push a Tag
    pub fn add(&mut self, tag: TagEntry) -> Result<(), StorageDriverError> {

        // make sure the tag name is present
        if tag.name.is_empty() {
            return Err(StorageDriverError::InternalMsg("Tag name is empty".to_string()));
        }

        // make sure the digest is present and valid
        if tag.digest.is_empty(){
            return Err(StorageDriverError::InternalMsg("Tag digest is empty".to_string()));
        }

        // Validate the digest now
        digest::parse(&tag.digest).map_err(|_|StorageDriverError::InternalMsg(format!("Trying to add the tag {} which has a malformed digest", tag.name)))?;

        // validate the date of the push
        if tag.pushed_at == 0 {
            return Err(StorageDriverError::InternalMsg("Tag 'pushed_at' field is empty".to_string()));
        }

        // if we got here it's safe to add the tag
        self.entries.push(tag);

        Ok(())

    }

    /// Find a tag with the specific name
    pub fn find(&self, tag_name_or_digest: &str) -> Option<TagEntry> {
        let result = self.entries.iter().rev().find(|entry| entry.name.as_str() == tag_name_or_digest);
        match result {
            Some(entry) => Some(entry.clone()),
            None => {
                let result = self.entries.iter().rev().find(|entry| entry.digest.as_str() == tag_name_or_digest);
                match result {
                    Some(entry) => Some(entry.clone()),
                    None => None
                }
            }
        }
    }

}
