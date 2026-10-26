//! Thin FFI over tevador/RandomX (randomx.h).
use std::ffi::c_void;
use std::os::raw::{c_int, c_ulong};

pub const FLAG_LARGE_PAGES: c_int = 1;
pub const FLAG_FULL_MEM: c_int = 4;

#[repr(C)]
pub struct Cache(c_void);
#[repr(C)]
pub struct Dataset(c_void);
#[repr(C)]
pub struct Vm(c_void);

extern "C" {
    pub fn randomx_get_flags() -> c_int;
    pub fn randomx_alloc_cache(flags: c_int) -> *mut Cache;
    pub fn randomx_init_cache(cache: *mut Cache, key: *const c_void, key_size: usize);
    pub fn randomx_release_cache(cache: *mut Cache);
    pub fn randomx_alloc_dataset(flags: c_int) -> *mut Dataset;
    pub fn randomx_dataset_item_count() -> c_ulong;
    pub fn randomx_init_dataset(d: *mut Dataset, c: *mut Cache, start: c_ulong, count: c_ulong);
    pub fn randomx_create_vm(flags: c_int, c: *mut Cache, d: *mut Dataset) -> *mut Vm;
    pub fn randomx_vm_set_dataset(vm: *mut Vm, d: *mut Dataset);
    pub fn randomx_destroy_vm(vm: *mut Vm);
    pub fn randomx_calculate_hash_first(vm: *mut Vm, input: *const c_void, size: usize);
    pub fn randomx_calculate_hash_next(
        vm: *mut Vm,
        next: *const c_void,
        size: usize,
        out: *mut c_void,
    );
}

/// Raw pointers shared across worker threads. RandomX datasets are read-only
/// once initialised, and each VM is owned by exactly one thread.
pub struct Shared<T>(pub *mut T);
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Shared<T> {}
unsafe impl<T> Send for Shared<T> {}
unsafe impl<T> Sync for Shared<T> {}
