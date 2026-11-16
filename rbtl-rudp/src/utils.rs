use crc32fast::Hasher;

pub (crate) type BoxedSlice<T> = OwnedSlice<T, Box<[T]>>;

/// An Owned Slice, *but* may also include a `begin` so that the view starts from there,
/// and an `end` so that the last elements are not part of the view
pub (crate) struct OwnedSlice<T, D: AsRef<[T]>> {
    _d: std::marker::PhantomData<T>,
    data: D,
    pub (crate) strip_begin: usize,
    pub (crate) strip_end: usize,
}

impl<T, D: AsRef<[T]>> std::fmt::Debug for OwnedSlice<T, D> where T: std::fmt::Debug {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // format StrippedBoxedSlice exactly as a slice starting from strip.
        self.as_slice().fmt(f)
    }
}

impl<T, D: AsRef<[T]>> OwnedSlice<T, D> {
    #[inline]
    pub fn new(data: D, strip_begin: usize) -> Self {
        Self::new_stripped(data, strip_begin, 0)
    }

    /// Same as `new`, but the last `strip_end` elements are not part of the slice either
    pub fn new_stripped(data: D, strip_begin: usize, strip_end: usize) -> Self {
        if strip_begin.saturating_add(strip_end) > data.as_ref().len() {
            panic!("OwnedSlice: cannot strip a higher amount than the length of original boxed slice: {} + {} > {}",
                strip_begin, strip_end, data.as_ref().len()
            );
        }
        OwnedSlice {
            _d: std::marker::PhantomData,
            data,
            strip_begin,
            strip_end,
        }
    }

    // #[inline]
    // pub fn with_added_strip(self, added_strip: usize) -> Self {
    //     let new_strip: usize = self.strip_begin.saturating_add(added_strip);
    //     OwnedSlice::new(self.data, new_strip)
    // }
    
    pub fn as_slice(&self) -> &[T] {
        let data = self.data.as_ref();
        &data[self.strip_begin..data.len() - self.strip_end]
    }
}

impl<T, D: AsRef<[T]>> AsRef<[T]> for OwnedSlice<T, D> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

pub fn crc32_hash(bytes: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(bytes);
    h.finalize()
}