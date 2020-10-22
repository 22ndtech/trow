use crate::registry_interface::media::MediaType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::registry_interface::registry_error::APIRegistryError;

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    #[serde(rename = "schemaVersion")]
    pub schema_version: i8,

    #[serde(rename = "config")]
    pub config: Layer,

    #[serde(default)]
    #[serde(rename = "layers")]
    pub layers: Vec<Layer>,

    #[serde(default)]
    #[serde(rename = "annotations")]
    pub annotations: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Layer {
    #[serde(rename = "mediaType")]
    pub media_type: MediaType,

    #[serde(default)]
    #[serde(rename = "size")]
    pub size: u64,

    #[serde(default)]
    #[serde(rename = "digest")]
    pub digest: String,

    #[serde(default)]
    #[serde(rename = "urls")]
    pub urls: Vec<String>,

    #[serde(default)]
    #[serde(rename = "annotations")]
    pub annotations: HashMap<String, String>,
}

impl Manifest {
    pub async fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
    pub fn to_json_blocking(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    // Parse bytes to Manifest
    pub async fn from_bytes(bytes: Vec<u8>) -> Result<Manifest, APIRegistryError> {
        serde_json::from_reader(bytes.as_slice())
            .map_err(|_e|APIRegistryError::InternalError {message: "Could not deserialize manifest".to_string(), details: String::default()})
    }

    pub fn total_size(&self) -> u64 {
        let mut total = self.config.size;

        for layer in self.layers.iter() {
            total += layer.size;
        }

        total
    }
}

#[cfg(test)]
mod test {
    use crate::serde_json::Result;
    use crate::registry_interface::manifest::Manifest;
    use crate::registry_interface::media::MediaType;

    #[test]
    fn manifest_basic() {
        // Parse a manifest JSON into a manifest
        let manifest_json = r#"
        {
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654,
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 16724,
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 73109,
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
    }
  ],
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"#;

        // Parse the string of data into serde_json::Value.
        let m: Result<Manifest> = crate::serde_json::from_str(manifest_json);
        assert!(m.is_ok());

        let m = m.unwrap();

        assert_eq!(2, m.schema_version);
        assert_eq!(2, m.annotations.len());

        // Config
        assert_eq!(
            "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
            m.config.digest
        );
        assert_eq!(7023, m.config.size);
        assert_eq!(MediaType::ManifestConfig, m.config.media_type);

        // Layers
        assert_eq!(3, m.layers.len());

        // First layer
        let layer = m.layers[0].clone();
        assert_eq!(32654, layer.size);
        assert_eq!(
            "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            layer.digest
        );
        assert_eq!(0, layer.urls.len());
        assert_eq!(0, layer.annotations.len());
        assert_eq!(MediaType::LayerTarGz, layer.media_type);

        // Second layer
        let layer = m.layers[1].clone();
        assert_eq!(16724, layer.size);
        assert_eq!(
            "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
            layer.digest
        );
        assert_eq!(0, layer.urls.len());
        assert_eq!(0, layer.annotations.len());
        assert_eq!(MediaType::LayerTarGz, layer.media_type);

        // Third layer
        let layer = m.layers[2].clone();
        assert_eq!(73109, layer.size);
        assert_eq!(
            "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
            layer.digest
        );
        assert_eq!(0, layer.urls.len());
        assert_eq!(0, layer.annotations.len());
        assert_eq!(MediaType::LayerTarGz, layer.media_type);
    }

    #[test]
    fn manifest_docker() {
        // Parse a manifest JSON into a manifest
        let manifest_json = r#"{
   "schemaVersion": 2,
   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
   "config": {
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "digest": "sha256:2c52ab475b702ac973d4882ea249dce73a2ade986fe2e153637d7ca5bf2e1a7d"
   },
   "layers": [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 45375208,
         "digest": "sha256:1c6172af85ee14a8db5a3a51d406b768dfa94d196c06d0d06d591507cf8199f0"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 10797476,
         "digest": "sha256:b194b0e3c928807cfabf081055a117585ba5bf6697f65b2fede02225a5d73ad2"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 4340140,
         "digest": "sha256:1f5ec00f35d5b2d1db6b8e925a3005c1a285365775028db0339903ddaeec4763"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 50084199,
         "digest": "sha256:93b1353672b6861da5f1b58b0eca02ec10373a25d2898bddafa1b4bae2271c55"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 214908493,
         "digest": "sha256:3d7f38db3cca2c74df9a146d8419f5bf79d79b18de9eaee6351dccde16ab1f4a"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 4163,
         "digest": "sha256:21e102f9fe89a18627c0ce50945bd1e0a11d0fecd4800bbbd999944d3940efc6"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 34505618,
         "digest": "sha256:d851ffed797cca8dad210a2ba6cb4ef75bffb0702231ad4f532f3e093e691228"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 2382597,
         "digest": "sha256:a45031e28c684e562a89c763024b7c76eea28bb32e3f982039b0a119a44b8238"
      },
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 296,
         "digest": "sha256:ca3c1414856f868bb11c63c067750f71d9ac0c9bc24eef5ced9094fda5db913a"
      }
   ]
}
"#;

        // Parse the string of data into serde_json::Value.
        let m: Result<Manifest> = crate::serde_json::from_str(manifest_json);
        assert!(m.is_ok());

        let m = m.unwrap();

        assert_eq!(2, m.schema_version);
        //assert_eq!(MediaType::ManifestDockerV2, m.media_type);

        // Config
        assert_eq!(
            "sha256:2c52ab475b702ac973d4882ea249dce73a2ade986fe2e153637d7ca5bf2e1a7d",
            m.config.digest
        );
        assert_eq!(0, m.config.size);
        assert_eq!(MediaType::ManifestDockerConfig, m.config.media_type);

        // Layers
        assert_eq!(9, m.layers.len());

        // First layer
        let layer = m.layers[0].clone();
        assert_eq!(45375208, layer.size);
        assert_eq!(
            "sha256:1c6172af85ee14a8db5a3a51d406b768dfa94d196c06d0d06d591507cf8199f0",
            layer.digest
        );
        assert_eq!(0, layer.urls.len());
        assert_eq!(0, layer.annotations.len());
        assert_eq!(MediaType::LayerDockerTarGz, layer.media_type);

    }
}
