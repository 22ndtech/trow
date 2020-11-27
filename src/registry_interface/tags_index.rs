use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use crate::registry_interface::tag_entry::{TagEntry, TagEntries};
use serde::{Deserialize, Serialize};
use crate::registry_interface::{digest, StorageDriverError};

/// This struct contains the list of tags for a specific name(space)
#[derive(Serialize, Deserialize, Debug)]
pub struct TagsIndex {

    /// This is the name(space) containing the tags
    pub name: String,

    /// Indicates whether TAGs inside this name(space) can be overwritten
    /// This flag can overridden per TAG
    pub immutable: bool,

    /// List of tags and their properties
    /// The key is the tag name, the value is a set of properties for the TAG
    tags: RwLock<HashMap<String, TagEntries>>,

    /// This is the index between the manifest digest and the tag name
    /// This is necessary in case we have a delete by digest to know which Tag we need to delete as well
    /// This index is used for deletion purposes only.
    index: RwLock<HashMap<String, HashSet<String>>>,

}

impl TagsIndex {

    pub fn new(name: &str, immutable: bool) -> TagsIndex {
        TagsIndex {
            name: name.to_string(),
            immutable,
            tags: Default::default(),
            index: Default::default()
        }
    }

    /// Serialise the index to json
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Parse bytes back to the Tags Index
    pub fn from_bytes(bytes: Vec<u8>) -> Result<TagsIndex, StorageDriverError> {
        serde_json::from_reader(bytes.as_slice())
            .map_err(|_e|StorageDriverError::InternalMsg("Could not deserialize tags index".to_string()))
    }

    // Returns a list of tags
    pub fn list(&self) -> Vec<String> {
        let tags = self.tags.read();

        if tags.is_err() {
            return vec![];
        }

        tags.unwrap().keys().map(|e| e.to_string()).collect()
    }

    // ---------------------------------------------------------------------------------------------
    // TAG SET
    // This is a helper method which loops through the whole index of the namespace
    // and returns a list of digest strings which the tag points to
    fn delete_tag_for_digest(&self, digest: &str, tag_name: &str) -> Result<(), StorageDriverError> {

        let mut tag_set = self.get_tag_set(digest)?;
        tag_set.remove(tag_name);

        if tag_set.is_empty() {
            self.delete_tag_set(digest)?;
        } else {
            self.write_tag_set(digest, tag_set)?;
        }

        Ok(())
    }

    // Adds a tag to a tag set for a specific digest
    fn add_tag_for_digest(&self, digest: &str, tag_name: &str) -> Result<(), StorageDriverError> {

        let mut tag_set = self.get_tag_set(digest)?;
        tag_set.insert(tag_name.to_string());
        self.write_tag_set(digest, tag_set)?;

        Ok(())
    }


    // deletes the whole tag set based on the digest
    fn delete_tag_set(&self, digest: &str) -> Result<(), StorageDriverError>{
        let mut index = self.index.write()
            .map_err(|_|StorageDriverError::InternalMsg("Could get a guard lock to index".to_string()))?;

        index.remove_entry(digest);

        Ok(())
    }

    // retrieve the hashset of tags from the index based on the digest
    fn get_tag_set(&self, digest: &str) -> Result<HashSet<String>, StorageDriverError>{
        let index = self.index.read()
            .map_err(|_|StorageDriverError::InternalMsg("Could get a guard lock to index".to_string()))?;

        let tags = index.get(digest);
        match tags {
            None => Ok(HashSet::new()),
            Some(tags) => Ok(tags.clone())
        }

    }

    // writes back the hash tag in the index
    fn write_tag_set(&self, digest: &str, tags_hash_set: HashSet<String>) -> Result<(), StorageDriverError>{
        let mut index = self.index.write()
            .map_err(|_|StorageDriverError::InternalMsg("Could get a guard lock to index".to_string()))?;

        index.insert(digest.to_string(), tags_hash_set);

        Ok(())
    }

    // ---------------------------------------------------------------------------------------------

    // writes back the tag entries in the tags
    fn write_tag_entries(&self, tag_name: &str, tag_entries: TagEntries) -> Result<(), StorageDriverError>{
        let mut tags = self.tags.write()
            .map_err(|_|StorageDriverError::InternalMsg("Could get a guard lock to tags".to_string()))?;

        tags.insert(tag_name.to_string(), tag_entries);

        Ok(())
    }

    fn remove_tag(&self, name: &str) -> Result<(), StorageDriverError> {
        let mut tags = self.tags.write()
            .map_err(|_|StorageDriverError::InternalMsg("Could get a guard lock to tags".to_string()))?;

        // remove the whole entry
        tags.remove(name);

        Ok(())
    }

    /// Returns a vector with all the manifest digests for a specific tag
    pub fn get_digests_for_tag(&self, tag: &str) -> Result<Vec<String>, StorageDriverError> {

        let tag_entries = self.get_tag(tag)?;
        if tag_entries.is_none() {
            return Ok(vec![]);
        }

        // Safe to unwrap
        let tag_entries = tag_entries.unwrap();

        // return al digest
        Ok(tag_entries.all_digest())

    }

    /// Gets a tag
    pub fn get_tag(&self, tag_or_digest: &str) -> Result<Option<TagEntries>, StorageDriverError> {

        let tags = self.tags.read()
            .map_err(|_|StorageDriverError::InternalMsg("Could get a guard lock to tags".to_string()))?;

        let tag_entry = tags.get(tag_or_digest);
        if tag_entry.is_none() {
            return Ok(None);
        }

        Ok(Some(tag_entry.unwrap().clone()))

    }

    /// Deletes a tag and its index
    pub fn delete_tag(&mut self, tag_or_digest: &str) -> Result<(), StorageDriverError> {

        // detect if it's a delete by tag or digest by trying to parse the digest
        let digest = digest::parse(tag_or_digest);

        // IMPORTANT!
        // Because the tag entries contain potentially multiple copies of the tag, one for each digest
        // then this method, when deleting by digest, deletes only the entries in the tag, but not the
        // parent tag itself, unless the tag how no more entries (versions)
        if digest.is_ok() {
            let digest = digest.unwrap();

            // 1. if it is a digest, then retrieve all the tags with an entry containing that digest
            let tags_for_digest = self.get_tag_set(&digest.to_string())?;

            // loop through each tag
            for tag_name in tags_for_digest.iter() {
                // get the tag - if it exists, by its name
                let tag_entries = self.get_tag(tag_name);

                // if it does exist, remove the entry with the specified digest
                if tag_entries.is_ok() {
                    let tag_entries = tag_entries.unwrap();

                    if tag_entries.is_some() {

                        let mut tag_entries = tag_entries.unwrap();
                        // delete by digest
                        tag_entries.delete_by_digest(&digest.to_string());

                        // if there is no more tags in the entry, then remove the whole entry
                        if tag_entries.is_empty() {
                            // delete the whole tag entry
                            self.remove_tag(tag_name)?;
                        } else {
                            // set the tag entries back
                            self.write_tag_entries(tag_name, tag_entries)?;
                        }

                        // Now remove the tag entry
                        self.delete_tag_for_digest(&digest.to_string(), tag_name)?;
                    }
                }
            }
            return Ok(());
        }

        // if we got here, then it's not a delete by digest, but it's a delete by tag
        // So we can safely remove the whole tag.
        // We also need to cleanup the index - so find all the digests which contain this specific tag name
        // and remove the tag value from the hashset
        // First remove the TAG, which is the safest option

        let tags = self.get_tag(tag_or_digest)?;

        if tags.is_none() {
            return Err(StorageDriverError::InternalMsg(format!("Failed to retrieve tag for {} {}", self.name, tag_or_digest)));
        }

        // Delete the tag now
        self.remove_tag(tag_or_digest)?;

        // safely unwrap
        let tags = tags.unwrap();

        let digest_list: Vec<String> = tags.entries().iter().map(|e| e.digest.clone()).collect();

        for digest in digest_list.iter() {
            self.delete_tag_for_digest(digest, tag_or_digest)?;
        }

        Ok(())
    }

    /// Adds the tag
    pub fn add_tag(&mut self, tag: TagEntry) -> Result<(), StorageDriverError> {

        let tags = self.tags.write();

        if tags.is_err() {
            return Err(StorageDriverError::InternalMsg(format!("Failed to read tag: {:#?}", tag)));
        }

        let mut tags = tags.unwrap();

        // check if the same tag exists
        let entries = tags.get(tag.name.as_str());

        let mut entries = match entries {
            None => TagEntries::new(),
            Some(entries) => entries.clone()
        };

        // if there are no entries, then just add this tag
        if entries.is_empty() {
            // insert the entries. The entries.add method already make sure the tag_name is not empty
            // push the tag: we are using the add method because we are making
            // additional validations in there. Propagate the error if the validations fail
            entries.add(tag.clone())?;

            // insert the entries. The entries.add method already make sure the tag_name is not empty
            tags.insert(tag.name.clone(), entries.clone());

            // Add the tag to the tag set for the specific digest
            self.add_tag_for_digest(&tag.digest, &tag.name)?;

            return Ok(());
        }

        // if we got here it means there were previous entries.
        // if a previous tag did exist, then we need to check whether this name(space) has
        // immutable tags - if so skip adding the tag
        if self.immutable {
            let details = format!("Name(space) {} is immutable. So the TAG {:#?} could not be added because there is already one", self.name, tag);
            log::warn!("{}", &details);
            return Err(StorageDriverError::InternalMsg(format!("Failed to insert tag: {:#?}", &tag)));
        }

        // if we got here it means that we allow pushing tags with the same tag name

        // Because we are using an array and we always push to it, the last version of the tag
        // is always the last entry in the array (TagEntries)

        // check if there is a tag with the same digest
        // There cannot be two tags with the same digest and same name
        let existing_tag = entries.find(&tag.digest);

        // If a previous tag with the same digest is found then we have nothing more to do here
        if existing_tag.is_some() {
            return Ok(());
        }

        // if a previous TAG with the same digest did not exist, then add it

        // insert the entries. The entries.add method already make sure the tag_name is not empty
        // push the tag: we are using the add method because we are making
        // additional validations in there. Propagate the error if the validations fail
        entries.add(tag.clone())?;

        // insert the entries. The entries.add method already make sure the tag_name is not empty
        tags.insert(tag.name.clone(), entries.clone());

        // Add the tag to the tag set for the specific digest
        self.add_tag_for_digest(&tag.digest, &tag.name)?;

        Ok(())
    }

    /// Returns the total namespace size
    pub fn namespace_size(&self) -> u64 {

        // Acquire the TAGS write lock
        let tags = self.tags.read();

        // if we cannot get the read lock, then we can return 0
        if tags.is_err() {
            return 0;
        }

        // safely unwrap
        let tags = tags.unwrap();

        let mut total: u64 = 0;
        for tag_entries in tags.values() {
            total += tag_entries.tags_size()
        }

        total
    }
}

