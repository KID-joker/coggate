use super::ServiceError;

pub(crate) fn dispatch_issue_version(version: &str) -> Result<(), ServiceError> {
    if version == agentgate_contracts::GENERATOR_VERSION_V1 {
        Ok(())
    } else {
        Err(ServiceError::UnsupportedGeneratorVersion)
    }
}

pub(crate) fn dispatch_verify_version(version: &str) -> Result<(), ServiceError> {
    if version == agentgate_contracts::GENERATOR_VERSION_V1 {
        Ok(())
    } else {
        Err(ServiceError::UnsupportedGeneratorVersion)
    }
}
