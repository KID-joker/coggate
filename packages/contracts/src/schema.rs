use schemars::{Schema, schema_for};

use crate::{PrivateChallengeMaterial, PublicChallenge, Submission};

pub fn public_challenge_schema() -> Schema {
    schema_for!(PublicChallenge)
}

pub fn private_material_schema() -> Schema {
    schema_for!(PrivateChallengeMaterial)
}

pub fn submission_schema() -> Schema {
    schema_for!(Submission)
}
