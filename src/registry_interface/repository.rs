use crate::registry_interface::repository_error;
use crate::registry_interface::repository_error::RepositoryError;
use crate::registry_interface::tag;
use crate::registry_interface::tag::Tag;

use lazy_static::lazy_static;
use regex::Regex;

use serde::{Deserialize, Serialize};
use crate::registry_interface::digest::DigestAlgorithm;

// Repository is the implementation of the repository spec:
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#overview
// 1. A repository name is broken up into path components.
// 2. A component of a repository name MUST begin with one or more lowercase alpha-numeric characters.
// 3. Subsequent lowercase alpha-numeric characters are OPTIONAL and MAY be separated by periods, dashes or underscores.
// More strictly, it MUST match the regular expression [a-z0-9]+(?:[._-][a-z0-9]+)*.

lazy_static! {
    static ref REGEX_COMPONENT: Regex = Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*").unwrap();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Repository {
    // This is the whole name(space)
    #[serde(default)]
    pub name: String,

    // This is the whole reference
    #[serde(default)]
    pub reference: String,

    // This is the parsed namespace
    #[serde(default)]
    pub components: Vec<String>,

    // This is the parsed reference
    pub tag: Tag,
}

pub fn new_with_reference(name: &str, reference: &str) -> Result<Repository, RepositoryError> {
    // parse the name(space)
    let mut repository = new(name)?;

    // set the reference
    repository.reference = reference.clone().to_string();

    // parse the tag
    let tag_repo = tag::new(reference)?;

    // assign it to the repository
    repository.tag = tag_repo;

    // return it
    Ok(repository)
}

// Create a new repository from the URI request
// TODO: handle the components with whitespace - whitespace seems to be allowed in the specs
pub fn new(name: &str) -> Result<Repository, RepositoryError> {
    // check that the maximum amount of chars for the name is 255
    if name.len() > 255 {
        return Err(repository_error::from(format!(
            "Repository name max length should be less than 255 chars - we got: {}",
            name.len()
        )));
    }

    // split the repository name into components via the: `/` char
    let components = name
        .split("/")
        .map(|token| String::from(token))
        .collect::<Vec<String>>();

    // verify now that each component is valid
    for component in &components {
        // if it does not match then return an error!
        if !REGEX_COMPONENT.is_match(component) {
            return Err(repository_error::from(format!(
                "Repository component is invalid: {}",
                &name
            )));
        }
    }

    Ok(Repository {
        name: name.clone().to_string(),
        reference: "".to_string(),
        components,
        tag: Tag {
            name: "".to_string(),
            algo: DigestAlgorithm::Sha256,
            version: "".to_string(),
            is_digest: false,
        },
    })
}

#[cfg(test)]
mod test {
    use crate::storage::digest::DigestAlgorithm;

    #[test]
    fn repository_no_tag_test() {
        let repo_name = String::from("library/nginx");
        let repo = super::new(&repo_name).expect(&*format!("Failed to parse repo: {}", &repo_name));
        assert_eq!(2, repo.components.len());
        assert_eq!("library", repo.components[0]);
        assert_eq!("nginx", repo.components[1]);
        assert_eq!(repo_name, repo.name);
        assert_eq!("", repo.tag.name);
        assert_eq!(DigestAlgorithm::default(), repo.tag.algo);
        assert_eq!("", repo.tag.version);
        assert_eq!(false, repo.tag.is_digest);
    }

    #[test]
    fn repository_with_empty_tag_test() {
        let repo_name = String::from("library/nginx");
        let repo = super::new_with_reference(&repo_name, "")
            .expect(&*format!("Failed to parse repo: {}", &repo_name));
        assert_eq!(2, repo.components.len());
        assert_eq!("library", repo.components[0]);
        assert_eq!("nginx", repo.components[1]);
        assert_eq!(repo_name, repo.name);
        assert_eq!("", repo.tag.name);
        assert_eq!(DigestAlgorithm::default(), repo.tag.algo);
        assert_eq!("", repo.tag.version);
        assert_eq!(false, repo.tag.is_digest);
    }

    #[test]
    fn repository_with_tag_test() {
        let repo_name = String::from("library/nginx");
        let reference = "nginx:1.18";
        let repo = super::new_with_reference(&repo_name, reference)
            .expect(&*format!("Failed to parse repo: {}", &repo_name));
        assert_eq!(2, repo.components.len());
        assert_eq!("library", repo.components[0]);
        assert_eq!("nginx", repo.components[1]);
        assert_eq!(repo_name, repo.name);
        assert_eq!(reference, repo.reference);
        assert_eq!("nginx", repo.tag.name);
        assert_eq!(DigestAlgorithm::default(), repo.tag.algo);
        assert_eq!("1.18", repo.tag.version);
        assert_eq!(false, repo.tag.is_digest);
    }

    #[test]
    fn repository_basic_test() {
        let repo_name = String::from("library");
        let reference = "nginx:latest";
        let repo = super::new_with_reference(&repo_name, reference)
            .expect(&*format!("Failed to parse repo: {}", &repo_name));
        assert_eq!(1, repo.components.len());
        assert_eq!("library", repo.components[0]);
        assert_eq!(repo_name, repo.name);
        assert_eq!(reference, repo.reference);
        assert_eq!("nginx", repo.tag.name);
        assert_eq!("latest", repo.tag.version);
        assert_eq!(false, repo.tag.is_digest);
    }

    #[test]
    fn repository_test() {
        let repo_name = String::from("library");
        let reference = "debian:unstable-20200803-slim";
        let repo = super::new_with_reference(&repo_name, reference)
            .expect(&*format!("Failed to parse repo: {}", &repo_name));
        assert_eq!(1, repo.components.len());
        assert_eq!("library", repo.components[0]);
        assert_eq!(repo_name, repo.name);
        assert_eq!(reference, repo.reference);
        assert_eq!("debian", repo.tag.name);
        assert_eq!("unstable-20200803-slim", repo.tag.version);
        assert_eq!(false, repo.tag.is_digest);
    }

    #[test]
    fn repository_image_version_and_digest_test() {
        let repo_name = String::from("frolvlad");
        let reference = "alpine-miniconda3:python3.7@sha256:9bc9c096713a6e47ca1b4a0d354ea3f2a1f67669c9a2456352d28481a6ce2fbe";
        let repo = super::new_with_reference(&repo_name, reference)
            .expect(&*format!("Failed to parse repo: {}", &repo_name));
        assert_eq!(1, repo.components.len());
        assert_eq!("frolvlad", repo.components[0]);
        assert_eq!(repo_name, repo.name);
        assert_eq!(reference, repo.reference);
        assert_eq!("alpine-miniconda3", repo.tag.name);
        assert_eq!(
            "9bc9c096713a6e47ca1b4a0d354ea3f2a1f67669c9a2456352d28481a6ce2fbe",
            repo.tag.version
        );
        assert!(repo.tag.is_digest);
    }

    #[test]
    fn repository_basic_with_slash_prefix_test() {
        let repo_name = String::from("/library");
        let repo = super::new(&repo_name);
        assert!(
            repo.is_err(),
            "repo should not start with a forward slash /"
        );
    }

    #[test]
    fn repository_complex_test() {
        let repo_name = String::from("lib/crane/reg/test/amd64/nginx");
        let repo = super::new(&repo_name);
        assert!(repo.is_ok(), "complex repo should be parsed fine");
        let repo = repo.unwrap();
        assert_eq!(6, repo.components.len());
        assert_eq!("lib", repo.components[0]);
        assert_eq!("crane", repo.components[1]);
        assert_eq!("reg", repo.components[2]);
        assert_eq!("test", repo.components[3]);
        assert_eq!("amd64", repo.components[4]);
        assert_eq!("nginx", repo.components[5]);
    }

    #[test]
    fn repository_complex_with_space_test() {
        let repo_name = String::from("lib/crane/reg/test rust/amd64/nginx");
        let repo = super::new(&repo_name);
        assert!(repo.is_ok(), "complex repo should be parsed fine");
        let repo = repo.unwrap();
        assert_eq!(6, repo.components.len());
        assert_eq!("lib", repo.components[0]);
        assert_eq!("crane", repo.components[1]);
        assert_eq!("reg", repo.components[2]);
        assert_eq!("test rust", repo.components[3]);
        assert_eq!("amd64", repo.components[4]);
        assert_eq!("nginx", repo.components[5]);
    }
}
