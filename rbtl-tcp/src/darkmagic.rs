
use std::cell::UnsafeCell;

// until SyncUnsafeCell is stable...
pub (crate) struct SyncUnsafeCell<T>(pub (crate) UnsafeCell<T>);

impl<T> SyncUnsafeCell<T> {
    pub fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}

// same bounds as std's SyncUnsafeCell: Send is derived automatically (only if T: Send)
unsafe impl<T: Sync> Sync for SyncUnsafeCell<T> {}

impl<T> std::fmt::Debug for SyncUnsafeCell<T> where T: std::fmt::Debug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.get().fmt(f)
    }
}