use crate::{registry_interface::manifest::Manifest, types::ManifestReader};
use crate::registry_interface::file::FileInfo;
use crate::registry_interface::digest::{DigestAlgorithm, Digest};
use std::io::Write;
use crate::registry_interface::tag::Tags;

pub mod digest;
pub mod index;
pub mod manifest;
pub mod media;
pub mod repository;
pub mod repository_error;
pub mod registry_error;
pub mod tag;
pub mod file;
pub mod tags_index;
pub mod tag_entry;

// TODO: implement the 'mount' and 'multi-arch' OCI spec

//==================================================================================================\
// Storage Driver Error
type Result<T> = std::result::Result<T, StorageDriverError>;
#[derive(Debug)]
pub struct StorageDriverError {
    pub details: String
}

// Display trait for the error
impl std::fmt::Display for StorageDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Storage driver error: {}", self.details)
    }
}

impl std::error::Error for StorageDriverError {}

impl StorageDriverError {
    pub fn new(details: &str) -> StorageDriverError {
        StorageDriverError {
            details: details.to_string()
        }
    }

    pub fn from(details: String) -> StorageDriverError {
        StorageDriverError {
            details
        }
    }
}

//==================================================================================================

// Super trait
pub trait RegistryStorage: TagStorage + ManifestStorage + BlobStorage {
    /// Whether the specific name(space) exists
    fn exists(&self, name: &String) -> Result<bool>;

    /// Whether the driver supports processing of data chunks in a streaming mode
    /// For example when the client uploads chunks of data, instead of buffering them
    /// in memory and then passing the full data, the driver can process single chunks
    /// individually. This significantly decrease the memory usage of the registry
    fn support_streaming(&self) -> bool;
}

// This trait handles the Tag operations
pub trait TagStorage {
    /// List TAGS
    /// GET: /v2/<name>/tags/list
    fn tags(&self, name: &str) -> Tags;

    // Adds a tag to the tag list
    fn add_tag(&self, name: &str, digest: &str) -> Result<()>;

    /// Allows to link a tag to its digest
    fn link_tag(&self, name: &str, tag: &str, algo: &DigestAlgorithm, hash: &str, manifest: &Manifest) -> Result<()>;
}

// This trait handles all the necessary Manifest Operations (get, save delete)
pub trait ManifestStorage {
    /// Fetch the manifest identified by name and reference where reference can be a tag or digest.
    /// A HEAD request can also be issued to this endpoint to obtain resource information without receiving all data.
    /// We return a reader object which will stream the bytes of the manifest. It's important *not* to serialize the
    /// manifest as we must return the same bytes that were sent.
    /// GET: /v2/<name>/manifests/<reference>
    /// HEAD: /v2/<name>/manifests/<reference>
    fn get_manifest(&self, name: &str, tag: &str) -> Result<ManifestReader>;

    // Stores should take a reader that has the data, possibly a second method that returns byte array

    /// Put the manifest identified by name and reference where reference can be a tag or digest.
    /// PUT: /v2/<name>/manifests/<reference>
    fn store_manifest(&self, name: &str, tag: &str, algo: &DigestAlgorithm, hash: &str, data: &[u8]) -> Result<()>;

    /// Store a manifest via Writer trait for drivers which support it
    fn store_manifest_with_writer(&self, name: &str, tag: &str) -> Result<Box<dyn Write>>;

    /// Delete the manifest identified by name and reference. Note that a manifest can only be deleted by digest.
    /// DELETE: /v2/<name>/manifests/<reference>
    fn delete_manifest(&self, name: &str, reference: &str, digest: Option<Digest>) -> Result<()>;

    /// Whether the specific manifest exists
    fn has_manifest(&self, name: &str, algo: &DigestAlgorithm, reference: &str) -> bool;
}

pub trait BlobStorage {
    /// Retrieve the blob from the registry identified by digest.
    /// A HEAD request can also be issued to this endpoint to obtain resource information without receiving all data.
    /// GET: /v2/<name>/blobs/<digest>
    fn get_blob(&self, name: &str, algo: &DigestAlgorithm, reference: &str) -> Result<Vec<u8>>;

    /// Delete the blob identified by name and digest
    /// DELETE: /v2/<name>/blobs/<digest>
    fn delete_blob(&self, name: &str, algo: &DigestAlgorithm, reference: &str) -> Result<()>;

    /// Initiate a resumable blob upload
    /// If successful, an upload location will be provided to complete the upload.
    /// Optionally, if the digest parameter is present, the request body will be used to complete the upload in a single request.
    /// POST: /v2/<name>/blobs/uploads/
    fn start_blob_upload(&self, name: &str, session_id: &str) -> Result<()>;

    /// Retrieve status of upload identified by session_id.
    /// The primary purpose of this endpoint is to resolve the current status of a resumable upload.
    /// GET: /v2/<name>/blobs/uploads/<session_id>
    fn status_blob_upload(&self, name: &str, session_id: &str) -> FileInfo;

    /// Upload a chunk of data for the specified upload.
    /// PATCH: /v2/<name>/blobs/uploads/<session_id>
    /// This method has the session_id as a parameter because at this point we don't know the final
    /// file name. So the data needs to be appended to a temporary file/location with the session_id
    /// as its identifier
    fn store_blob(&self, name: &str, session_id: &str, data: &[u8]) -> Result<()>;


    /// If the driver supports streaming then the service uses this trait method to get back a Write
    /// Trait (a File or a TcpStream fir example) and will push data to the stream (Write) so that
    /// the Registry does not have to buffer in memory all the chunks and instead it just forwards them to the
    /// driver
    fn store_blob_with_writer(&self, _name: &str, session_id: &str) -> Result<Box<dyn Write>>;

    /// Complete the upload specified by session_id, optionally appending the body as the final chunk.
    /// PUT: /v2/<name>/blobs/uploads/<session_id>
    /// In this case we need both the session id and the digest because we need to move/rename
    /// the session_id temporary file/location to the final one which is supposed to have the
    /// digest as its identifier (file name or location id)
    /// Returns the bytes of the final file, necessary to verify the digest
    fn end_blob_upload(&self, name: &str, session_id: &str, algo: &DigestAlgorithm, reference: &str) -> Result<Vec<u8>>;

    /// Cancel outstanding upload processes, releasing associated resources.
    /// If this is not called, the unfinished uploads will eventually timeout.
    /// DELETE: /v2/<name>/blobs/uploads/<session_id>
    /// Here we need to delete the existing temporary file/location based on its identifier: the session_id
    fn cancel_blob_upload(&self, name: &str, session_id: &str) -> Result<()>;

    /// Whether the specific blob exists
    fn has_blob(&self, name: &str, algo: &DigestAlgorithm, reference: &str) -> FileInfo;
}
