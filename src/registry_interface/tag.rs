use crate::registry_interface::digest;
use crate::registry_interface::repository_error;
use crate::registry_interface::repository_error::RepositoryError;
use crate::registry_interface::digest::DigestAlgorithm;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Tag {
    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub algo: DigestAlgorithm,

    #[serde(default)]
    pub version: String,

    #[serde(default)]
    pub is_digest: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Tags {
    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default)]
    pub size: u64
}

impl Tags {
    pub fn empty() -> Tags {
        Tags {
            name: "".to_string(),
            tags: vec![],
            size: 0
        }
    }
}

pub fn new(component: &str) -> Result<Tag, RepositoryError> {
    // if the component is empty it makes no sense to parse it, so return an empty tag
    if component.is_empty() {
        return Ok(Tag {
            name: "".to_string(),
            algo: DigestAlgorithm::Sha256,
            version: "".to_string(),
            is_digest: false,
        });
    }

    // if it contains an @ then it's a digest
    let (split_by, is_digest) = if component.contains("@") {
        ("@", true)
    } else {
        (":", false)
    };

    // split based on the split_by string
    let tokens = component
        .split(split_by)
        .map(|token| String::from(token))
        .collect::<Vec<String>>();
    let tokens_len = tokens.len();

    // In case of digest we need to have 2 tokens
    // otherwise we might just have the image name and we need to consider it as `latest` tag
    if is_digest && tokens_len < 2 {
        return Err(repository_error::from(format!(
            "Component {} cannot be parsed into a TAG",
            &component
        )));
    }

    // if it's digest then we need to split further between the algo and the digest
    // sha256:_
    let (algo, version) = if is_digest {
        // Split and validate the digest
        let digest = digest::parse(&tokens[1])?;
        // return it as a tuple
        (digest.algo, digest.hash)
    } else {
        // if is not a digest and we have only 1 token, then it's a latest version!
        if tokens_len == 1 {
            (DigestAlgorithm::default(), String::from("latest"))
        } else {
            (DigestAlgorithm::default(), String::from(&tokens[1]))
        }
    };

    let name = String::from(&tokens[0]);

    // Image name
    let name: String = if name.contains(":") {
        let tokens = component
            .split(":")
            .map(|token| String::from(token))
            .collect::<Vec<String>>();
        String::from(&tokens[0])
    } else {
        name
    };

    Ok(Tag {
        name,
        version,
        is_digest,
        algo,
    })
}

#[cfg(test)]
mod test {
    use crate::registry_interface::digest::DigestAlgorithm;

    #[test]
    fn tag_simple() {
        let tag = "nginx:latest";
        let tag = super::new(tag).expect(&*format!("Failed to parse tag: {}", &tag));
        assert_eq!("nginx", tag.name);
        assert_eq!("latest", tag.version);
        assert_eq!(DigestAlgorithm::default(), tag.algo);
        assert_eq!(false, tag.is_digest);
    }

    #[test]
    fn tag_no_double_col() {
        let tag = "nginx:latest:test";
        let tag = super::new(tag.clone()).expect(&*format!("Failed to parse tag: {}", &tag));
        assert_eq!("nginx", tag.name);
        assert_eq!("latest", tag.version);
        assert_eq!(DigestAlgorithm::default(), tag.algo);
        assert_eq!(false, tag.is_digest);
    }

    #[test]
    fn tag_no_version() {
        let tag = "nginx";
        let tag = super::new(tag.clone()).expect(&*format!("Failed to parse tag: {}", &tag));
        assert_eq!("nginx", tag.name);
        assert_eq!("latest", tag.version);
        assert_eq!(DigestAlgorithm::default(), tag.algo);
        assert_eq!(false, tag.is_digest);
    }

    #[test]
    fn tag_digest_simple() {
        let tag = "nginx@sha256:09490543485983759834745983745785";
        let tag = super::new(tag.clone()).expect(&*format!("Failed to parse tag: {}", &tag));
        assert_eq!("nginx", tag.name);
        assert_eq!("09490543485983759834745983745785", tag.version);
        assert_eq!(DigestAlgorithm::Sha256, tag.algo);
        assert!(tag.is_digest);
    }

    #[test]
    fn tag_digest_wrong_format_simple() {
        let tag = "nginx@sha256:094905434859837598347459837457ß85";
        let tag = super::new(tag.clone());
        assert!(tag.is_err(), "tag should not pass the digest regex format");
    }

    #[test]
    fn tag_digest_complex() {
        let tag = "alpine-miniconda3:python3.7@sha256:9bc9c096713a6e47ca1b4a0d354ea3f2a1f67669c9a2456352d28481a6ce2fbe";
        let tag = super::new(tag.clone()).expect(&*format!("Failed to parse tag: {}", &tag));
        assert_eq!("alpine-miniconda3", tag.name);
        assert_eq!(
            "9bc9c096713a6e47ca1b4a0d354ea3f2a1f67669c9a2456352d28481a6ce2fbe",
            tag.version
        );
        assert_eq!(DigestAlgorithm::Sha256, tag.algo);
        assert!(tag.is_digest);
    }
}
