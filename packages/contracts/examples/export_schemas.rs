use agentgate_contracts::{private_material_schema, public_challenge_schema, submission_schema};
use schemars::Schema;
use std::error::Error;
use std::fs;
use std::path::Path;

fn write_schema(path: &Path, schema: Schema) -> Result<(), Box<dyn Error>> {
    let mut json = serde_json::to_string_pretty(&schema)?;
    json.push('\n');
    fs::write(path, json)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let schemas_dir = Path::new("schemas");
    fs::create_dir_all(schemas_dir)?;

    write_schema(
        &schemas_dir.join("public-challenge.schema.json"),
        public_challenge_schema(),
    )?;
    write_schema(
        &schemas_dir.join("private-challenge-material.schema.json"),
        private_material_schema(),
    )?;
    write_schema(
        &schemas_dir.join("submission.schema.json"),
        submission_schema(),
    )?;

    Ok(())
}
