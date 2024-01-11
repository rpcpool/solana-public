use std::{collections::HashMap, fs, path::PathBuf};

use solana_sdk::pubkey::Pubkey;

pub enum PreOrPostDatum {
    PreDatum,
    PostDatum,
}

pub type ProgramDatumInclusions = HashMap<Pubkey, DatumInclusion>;
pub type InclusionsFromConfig = HashMap<String, DatumInclusion>;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DatumInclusion {
    #[serde(default)]
    pub pre: bool,
    #[serde(default)]
    pub post: bool,
    #[serde(default)]
    pub length_exclusions: Vec<usize>,
}

impl DatumInclusion {
    pub fn can_include_datum(&self, pre_or_post: &PreOrPostDatum, data: &[u8]) -> bool {
        let allow_pre_post = match pre_or_post {
            PreOrPostDatum::PreDatum => self.pre,
            PreOrPostDatum::PostDatum => self.post,
        };

        if !allow_pre_post {
            return false;
        }

        !self.length_exclusions.contains(&data.len())
    }
}

#[derive(serde::Deserialize)]
struct GeyserConfigFileWithInclusions {
    #[serde(rename = "datumProgramInclusions")]
    pub datum_program_inclusions: InclusionsFromConfig,
}

pub fn load_datum_program_inclusions(paths: &Option<Vec<PathBuf>>) -> ProgramDatumInclusions {
    let mut datum_program_inclusions: ProgramDatumInclusions = HashMap::new();
    if let Some(paths) = paths {
        for path in paths {
            let file = fs::read(path);
            if !file.is_ok() {
                eprintln!("Unable to read JSON file: {:?} Skipping...", path);
                continue;
            }
            let json = serde_json::from_slice::<GeyserConfigFileWithInclusions>(&file.unwrap());
            if let Err(e) = json {
                eprintln!("Unable to parse JSON file {:?}: {:?} Skipping...", path, e);
                continue;
            }
            let inclusions_map = json.unwrap().datum_program_inclusions;
            for (pubkey, inc) in inclusions_map.iter() {
                let pk_parsed = pubkey.parse::<Pubkey>().expect(
                    format!(
                        "Bad pubkey provided to datumProgramInclusions in geyser config file {:?}",
                        path
                    )
                    .as_str(),
                );
                datum_program_inclusions.insert(pk_parsed, inc.clone());
            }
        }
    }
    datum_program_inclusions
}
