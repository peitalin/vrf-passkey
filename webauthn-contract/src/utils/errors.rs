use near_sdk::FunctionError;

#[derive(Debug, FunctionError)]
pub enum ContractError {
    InvalidChallengeFormat,
    MissingChallenge,
}
impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
impl ContractError {
    pub fn to_string(&self) -> String {
        match self {
            ContractError::InvalidChallengeFormat => "Invalid challenge format".to_string(),
            ContractError::MissingChallenge => "Missing challenge".to_string(),
        }
    }
}