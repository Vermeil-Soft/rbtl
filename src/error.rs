use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Error {
    pub msg: String,
    pub source: Option<Arc<dyn std::error::Error>>,
}

impl Error {
    pub fn new(msg: String) -> Self {
        Self { msg, source: None }
    }

    pub fn from_cause<E: std::error::Error + 'static>(msg: String, cause: E) -> Self {
        Self { msg, source: Some(Arc::new(cause)) }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(source) = &self.source {
            write!(f, "rbtl (orchestor) error {}: {}", self.msg, source)
        } else {
            write!(f, "rbtl (orchester) error {}", self.msg)
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source.as_ref().map(|a| &**a)
    }
}