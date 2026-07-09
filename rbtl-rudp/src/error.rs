use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Error {
    pub msg: String,
    pub source: Option<Arc<dyn std::error::Error + Sync + Send>>,
}

impl Error {
    pub fn new<I: Into<String>>(msg: I) -> Self {
        Self { msg: msg.into(), source: None }
    }

    pub fn from_cause<I: Into<String>, E: std::error::Error + Sync+ Send + 'static>(msg: I, cause: E) -> Self {
        Self { msg: msg.into(), source: Some(Arc::new(cause)) }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(source) = &self.source {
            write!(f, "rbtl-rudp error {}, cause {}", self.msg, source)
        } else {
            write!(f, "rbtl-rudp error {}", self.msg)
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source.as_ref().map(|a| &**a as &dyn std::error::Error)
    }
}