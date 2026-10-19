//! Compile the erasure contracts in both native and portable Wasm builds.
//! This catches dependency-feature regressions; it does not prove stack/register
//! erasure or browser-managed `CryptoKey` destruction.

const fn erases_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn dependency_secret_owners_require_erasure() {
    erases_on_drop::<aes::Aes256>();
}
