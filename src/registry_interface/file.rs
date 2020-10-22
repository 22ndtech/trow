use std::fs;
use std::time::SystemTime;
use log::error;
use serde::{Deserialize, Serialize};

// TODO: make is a Trait because we could have files or DB records or s3 objects etc...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfo {

    // Store the path of the file
    pub path: String,

    // The size of the file
    pub size: u64,

    // lat modified time of the file
    pub last_modified: u64,
}

impl FileInfo {

    // Returns an empty instance
    pub fn new_empty() -> FileInfo {
        FileInfo {
            path: String::new(),
            size: 0u64,
            last_modified: 0u64
        }
    }


    pub fn new(path: String) -> Result<FileInfo, std::io::Error> {
        // read the file metadata. If the file does not exist it propagates the error
        let metadata = fs::metadata(&path)?;

        // get the size
        let size = metadata.len();

        // read the last modified time
        let last_modified = metadata.modified()?;

        // from UNIX EPOC
        let last_modified = last_modified.duration_since(SystemTime::UNIX_EPOCH);

        // Check in case we could not read the timestamp
        let last_modified = match last_modified {
            Ok(n) => n.as_secs(),
            Err(_) => {
                error!("Could not read last modified time of file {:#?}", &path);
                0u64
            },
        };

        // return the FileInfo
        Ok(FileInfo {
            path,
            size,
            last_modified
        })
    }

    // returns whether the file exists
    pub fn exists(&self) -> bool {
        self.size > 0
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn file_info_test() {

        // Get the file info
        let file_info = super::FileInfo::new("Cargo.toml".to_string());

        // Make sure we have got a file info
        assert!(file_info.is_ok());

        // Unwrap the file info
        let file_info = file_info.unwrap();

        // Makes sure it exists
        assert!(file_info.exists());

        // make sure the path is set
        assert!(file_info.path.as_str().len() > 0);

        // make sure the last modified is set
        assert!(file_info.last_modified > 0);

    }
}

