//! Public evidence that an effect was reached through framework dispatch.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DispatchVia {
    pub model: String,
    pub registration_path: Vec<String>,
    pub dispatch_path: Vec<String>,
}
