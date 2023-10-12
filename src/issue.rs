

#[cfg(test)]
mod tests {
    use generic_array::{ArrayLength, GenericArray};
    use typenum::{U123, U1024};

    pub struct MySmallArray<N: ArrayLength>(GenericArray<u8, N>);
    pub struct MyBigArray<N: ArrayLength>(GenericArray<u8, N>);

    #[test]
    fn test_array_sizes() {
        use generic_array::{typenum::*, ArrayLength, GenericArray};

        struct Foo<T, N: ArrayLength> {
            data: GenericArray<T, N>,
        }

        // https://docs.rs/typenum/latest/typenum/operator_aliases/type.Prod.html
        type U12345 = Prod<U15, U823>;

        let foo = Foo::<i32, U12345> {
            data: GenericArray::default(),
        };

        let mut dest = [0i32; 12345];
        dest.copy_from_slice(&foo.data);

        assert_eq!(foo.data.len(), dest.len());
        // let big = MyBigArray::Sum::<U123, U1024>(GenericArray.default());
        // let mut big_bytes = [0u8; 1047];
        // big_bytes.copy_from_slice(&big.0);
    }
}


