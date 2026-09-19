//! One shared helper for the in-place constructors (`Blockchain::init`,
//! `BlockTable::init`, `ChainHeadsTable::init`, `NodeInfoState::init`):
//! lets an outer type that is itself still being constructed hand one of its
//! not-yet-initialized fields to the field type's **safe**
//! `init(&mut MaybeUninit<Self>)`, so the raw-pointer arithmetic stays in
//! exactly one place per level instead of being repeated at every call site.

use core::mem::MaybeUninit;

/// Views the not-yet-initialized field behind `p` as a `&mut MaybeUninit<T>`.
///
/// `MaybeUninit<T>` has the same size and alignment as `T` and places no
/// validity requirement on the bytes, so the cast is layout-sound for
/// uninitialized memory.
///
/// # Safety
/// `p` must be non-null, aligned, valid for writes of `T`, and not aliased by
/// any other live reference for the lifetime `'a` of the returned borrow.
pub(crate) unsafe fn field_slot<'a, T>(p: *mut T) -> &'a mut MaybeUninit<T> {
    unsafe { &mut *p.cast::<MaybeUninit<T>>() }
}
