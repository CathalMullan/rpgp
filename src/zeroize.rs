#[cfg(feature = "zeroize")]
pub type Zeroizing<T> = zeroize::Zeroizing<T>;

#[cfg(not(feature = "zeroize"))]
pub use shim::Zeroizing;

#[cfg(not(feature = "zeroize"))]
mod shim {
    use core::ops::{Deref, DerefMut};

    #[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
    #[repr(transparent)]
    pub struct Zeroizing<Z: ?Sized>(Z);

    impl<Z> Zeroizing<Z> {
        #[inline(always)]
        #[must_use]
        pub fn new(value: Z) -> Self {
            Self(value)
        }
    }

    impl<Z> Deref for Zeroizing<Z>
    where
        Z: ?Sized,
    {
        type Target = Z;

        #[inline(always)]
        fn deref(&self) -> &Z {
            &self.0
        }
    }

    impl<Z> DerefMut for Zeroizing<Z>
    where
        Z: ?Sized,
    {
        #[inline(always)]
        fn deref_mut(&mut self) -> &mut Z {
            &mut self.0
        }
    }

    impl<Z> From<Z> for Zeroizing<Z> {
        #[inline(always)]
        fn from(value: Z) -> Zeroizing<Z> {
            Zeroizing(value)
        }
    }

    impl<T, Z> AsRef<T> for Zeroizing<Z>
    where
        T: ?Sized,
        Z: AsRef<T> + ?Sized,
    {
        #[inline(always)]
        fn as_ref(&self) -> &T {
            self.0.as_ref()
        }
    }

    impl<T, Z> AsMut<T> for Zeroizing<Z>
    where
        T: ?Sized,
        Z: AsMut<T> + ?Sized,
    {
        #[inline(always)]
        fn as_mut(&mut self) -> &mut T {
            self.0.as_mut()
        }
    }
}
