
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

unsafe impl<T> Sync for SyncUnsafeCell<T> {}
unsafe impl<T> Send for SyncUnsafeCell<T> {}