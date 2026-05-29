//! Runtime-layer derive + attribute macros for ArkheForge.
//!
//! Three derives — `#[derive(ArkheComponent)]`, `#[derive(ArkheAction)]`,
//! `#[derive(ArkheEvent)]` — emit the sealed-trait impl plus the marker-trait
//! impl pinning `TYPE_CODE` / `SCHEMA_VERSION` (and, for `ArkheAction`,
//! `BAND` / `IDEMPOTENT`).
//!
//! One attribute — `#[arkhe_pure]` — asserts that an `Action::compute`
//! body conforms to E14.L1 Subset-Rust purity (clock / RNG / I/O / FFI
//! deny-list). Backed by `arkhe-subset-rust-check`.
//!
//! ## Compile-time validation
//!
//! * `#[arkhe(type_code = N)]` mandatory; `N` must lie in the appropriate
//!   reserved sub-range (or the shell-scoped extension range).
//! * First named struct field must be `schema_version: u16` (wire version tag).
//! * `#[arkhe(band = K)]` mandatory for `ArkheAction`; `K ∈ {1, 2, 3}`.
//! * `#[arkhe(idempotent)]` opt-in on `ArkheAction` — requires the struct
//!   to carry an `idempotency_key` field.
//! * Field-level `#[arkhe(canonical_sort)]` on `ArkheComponent` / `ArkheEvent`
//!   is allowed only on `Vec<T>` / `BTreeSet<T>` fields.
//!
//! ## Namespace
//!
//! Do not confuse with `arkhe-macros` (L0 kernel derives). This crate
//! targets the Runtime traits in `arkhe_forge_core::{component, action,
//! event, sealed}`; the L0 derive crate is orthogonal.

#![forbid(unsafe_code)]

use darling::{FromDeriveInput, FromField};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, Data, DataStruct, DeriveInput,
    Expr, Field, Fields, GenericArgument, Ident, Lit, PathArguments, Token, Type, TypeArray,
};

// ===================== Component =====================

#[derive(FromDeriveInput)]
#[darling(attributes(arkhe), supports(struct_named))]
struct ComponentAttrs {
    type_code: u32,
    #[darling(default = "default_schema_version")]
    schema_version: u16,
}

#[derive(FromField, Default)]
#[darling(attributes(arkhe), default)]
struct FieldAttrs {
    canonical_sort: bool,
}

fn default_schema_version() -> u16 {
    1
}

/// Derive `ArkheComponent` — emits the sealed-trait impl and the marker-trait
/// impl pinning `TYPE_CODE` and `SCHEMA_VERSION`.
///
/// See crate-level documentation for attribute grammar and validation rules.
#[proc_macro_derive(ArkheComponent, attributes(arkhe))]
pub fn derive_arkhe_component(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let attrs = match ComponentAttrs::from_derive_input(&input) {
        Ok(a) => a,
        Err(e) => return e.write_errors().into(),
    };
    match derive_component_impl(&input, attrs) {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_component_impl(input: &DeriveInput, attrs: ComponentAttrs) -> syn::Result<TokenStream2> {
    validate_type_code(attrs.type_code, TypeCodeKind::Component, &input.ident)?;
    validate_schema_version_first_field(&input.data, &input.ident)?;
    validate_canonical_sort_fields(&input.data)?;

    let name = &input.ident;
    let (impl_g, ty_g, where_g) = input.generics.split_for_impl();
    let type_code = attrs.type_code;
    let schema_version = attrs.schema_version;

    Ok(quote! {
        #[automatically_derived]
        impl #impl_g ::arkhe_forge_core::__sealed::__Sealed
            for #name #ty_g #where_g {}

        #[automatically_derived]
        impl #impl_g ::arkhe_forge_core::component::ArkheComponent
            for #name #ty_g #where_g
        {
            const TYPE_CODE: u32 = #type_code;
            const SCHEMA_VERSION: u16 = #schema_version;
        }
    })
}

// ===================== Action =====================

#[derive(FromDeriveInput)]
#[darling(attributes(arkhe), supports(struct_named))]
struct ActionAttrs {
    type_code: u32,
    #[darling(default = "default_schema_version")]
    schema_version: u16,
    band: u8,
    #[darling(default)]
    idempotent: bool,
}

/// Derive `ArkheAction` — emits the sealed-trait impl and the marker-trait
/// impl pinning `TYPE_CODE`, `SCHEMA_VERSION`, `BAND`, `IDEMPOTENT`.
///
/// See crate-level documentation for attribute grammar and validation rules.
#[proc_macro_derive(ArkheAction, attributes(arkhe))]
pub fn derive_arkhe_action(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let attrs = match ActionAttrs::from_derive_input(&input) {
        Ok(a) => a,
        Err(e) => return e.write_errors().into(),
    };
    match derive_action_impl(&input, attrs) {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_action_impl(input: &DeriveInput, attrs: ActionAttrs) -> syn::Result<TokenStream2> {
    validate_type_code(attrs.type_code, TypeCodeKind::Action, &input.ident)?;
    validate_schema_version_first_field(&input.data, &input.ident)?;
    validate_band(attrs.band, &input.ident)?;
    if attrs.idempotent {
        validate_idempotency_key_field(&input.data, &input.ident)?;
    }

    let name = &input.ident;
    let (impl_g, ty_g, where_g) = input.generics.split_for_impl();
    let type_code = attrs.type_code;
    let schema_version = attrs.schema_version;
    let band = attrs.band;
    let idempotent = attrs.idempotent;

    Ok(quote! {
        #[automatically_derived]
        impl #impl_g ::arkhe_forge_core::__sealed::__Sealed
            for #name #ty_g #where_g {}

        #[automatically_derived]
        impl #impl_g ::arkhe_forge_core::action::ArkheAction
            for #name #ty_g #where_g
        {
            const TYPE_CODE: u32 = #type_code;
            const SCHEMA_VERSION: u16 = #schema_version;
            const BAND: ::arkhe_forge_core::action::Band = #band;
            const IDEMPOTENT: bool = #idempotent;
        }

        // Kernel-side trait stack — paired with the forge-side stack
        // above so `Kernel::register_action::<Self>()` accepts this
        // type. The kernel's blanket
        // `impl<T: ActionDeriv + ActionCompute> Action for T` then
        // supplies the postcard-canonical default methods.
        //
        // `_sealed::Sealed` is `#[doc(hidden)] pub` in `arkhe-kernel`.
        // arkhe-macros (the kernel's own derive crate, on crates.io)
        // is the conventional emitter; arkhe-forge-macros is the
        // workspace-internal sibling and emits the same shape under
        // the same A11 sanctioned-derive convention.
        #[automatically_derived]
        impl #impl_g ::arkhe_kernel::state::traits::_sealed::Sealed
            for #name #ty_g #where_g {}

        #[automatically_derived]
        impl #impl_g ::arkhe_kernel::state::traits::ActionDeriv
            for #name #ty_g #where_g
        {
            const TYPE_CODE: ::arkhe_kernel::abi::TypeCode =
                ::arkhe_kernel::abi::TypeCode(#type_code);
            const SCHEMA_VERSION: u32 = #schema_version as u32;
        }

        #[automatically_derived]
        impl #impl_g ::arkhe_kernel::state::traits::ActionCompute
            for #name #ty_g #where_g
        {
            fn compute(
                &self,
                ctx: &::arkhe_kernel::state::ActionContext<'_>,
            ) -> ::std::vec::Vec<::arkhe_kernel::state::Op> {
                ::arkhe_forge_core::bridge::kernel_compute(self, ctx)
            }
        }
    })
}

// ===================== Event =====================

#[derive(FromDeriveInput)]
#[darling(attributes(arkhe), supports(struct_named))]
struct EventAttrs {
    type_code: u32,
    #[darling(default = "default_schema_version")]
    schema_version: u16,
}

/// Derive `ArkheEvent` — emits the sealed-trait impl and the marker-trait
/// impl pinning `TYPE_CODE` and `SCHEMA_VERSION`.
///
/// See crate-level documentation for attribute grammar and validation rules.
#[proc_macro_derive(ArkheEvent, attributes(arkhe))]
pub fn derive_arkhe_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let attrs = match EventAttrs::from_derive_input(&input) {
        Ok(a) => a,
        Err(e) => return e.write_errors().into(),
    };
    match derive_event_impl(&input, attrs) {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_event_impl(input: &DeriveInput, attrs: EventAttrs) -> syn::Result<TokenStream2> {
    validate_type_code(attrs.type_code, TypeCodeKind::Event, &input.ident)?;
    validate_schema_version_first_field(&input.data, &input.ident)?;
    validate_canonical_sort_fields(&input.data)?;

    let name = &input.ident;
    let (impl_g, ty_g, where_g) = input.generics.split_for_impl();
    let type_code = attrs.type_code;
    let schema_version = attrs.schema_version;

    Ok(quote! {
        #[automatically_derived]
        impl #impl_g ::arkhe_forge_core::__sealed::__Sealed
            for #name #ty_g #where_g {}

        #[automatically_derived]
        impl #impl_g ::arkhe_forge_core::event::ArkheEvent
            for #name #ty_g #where_g
        {
            const TYPE_CODE: u32 = #type_code;
            const SCHEMA_VERSION: u16 = #schema_version;
        }
    })
}

// ===================== Pure (E14.L1 Subset-Rust) =====================

/// `#[arkhe_pure]` — attribute macro asserting that an `Action::compute`-
/// style function body conforms to E14.L1 Subset-Rust purity. Backed by
/// `arkhe-subset-rust-check`; emits a `compile_error!` per violation
/// site. Spec anchor: E14.L1 (MC).
///
/// Uses the default `arkhe-subset-rust-check` policy (clock + RNG +
/// I/O + FFI deny-list); additive deny-list extensions through the
/// `Policy::*` constructors are non-breaking.
///
/// ## Usage
///
/// ```ignore
/// use arkhe_forge_core::arkhe_pure;
///
/// #[arkhe_pure]
/// fn compute(a: u32, b: u32) -> u32 {
///     a.wrapping_add(b).wrapping_mul(2)   // pure — passes
/// }
///
/// // The following triggers a compile error:
/// //   #[arkhe_pure]
/// //   fn compute_bad() -> u128 {
/// //       std::time::Instant::now().elapsed().as_nanos()  // E14.L1 violation
/// //   }
/// ```
///
/// The macro re-emits the original function unchanged on success, so it
/// has zero runtime cost and stacks with other attributes (`#[inline]`,
/// `#[cfg(...)]`, etc.).
#[proc_macro_attribute]
pub fn arkhe_pure(_args: TokenStream, item: TokenStream) -> TokenStream {
    let item_clone = item.clone();
    let item_fn = parse_macro_input!(item_clone as syn::ItemFn);
    let violations = arkhe_subset_rust_check::check_purity_default(&item_fn);
    if violations.is_empty() {
        return item;
    }
    let errors: TokenStream2 = violations
        .into_iter()
        .map(|v| {
            let msg = format!(
                "E14.L1 Subset-Rust purity violation: \
                 `{}` ({}). \
                 see arkhe-subset-rust-check policy.",
                v.denied_path, v.reason
            );
            quote! { ::core::compile_error!(#msg); }
        })
        .collect();
    let original: TokenStream2 = item.into();
    quote! {
        #errors
        #original
    }
    .into()
}

// ===================== Validation helpers =====================

#[derive(Copy, Clone)]
enum TypeCodeKind {
    Component,
    Action,
    Event,
}

impl TypeCodeKind {
    fn core_range(self) -> (u32, u32) {
        match self {
            Self::Component => (0x0003_0000, 0x0003_0EFF),
            Self::Action => (0x0001_0000, 0x0001_FFFF),
            Self::Event => (0x0003_0F00, 0x0003_FFFF),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Component => "ArkheComponent",
            Self::Action => "ArkheAction",
            Self::Event => "ArkheEvent",
        }
    }
}

const SHELL_RANGE: (u32, u32) = (0x0100_0000, 0xEFFF_FFFF);

fn validate_type_code(type_code: u32, kind: TypeCodeKind, name: &Ident) -> syn::Result<()> {
    let (core_lo, core_hi) = kind.core_range();
    let (shell_lo, shell_hi) = SHELL_RANGE;
    let in_core = (core_lo..=core_hi).contains(&type_code);
    let in_shell = (shell_lo..=shell_hi).contains(&type_code);
    if in_core || in_shell {
        return Ok(());
    }
    Err(syn::Error::new(
        name.span(),
        format!(
            "{} type_code 0x{:08X} out of range; core: 0x{:08X}..=0x{:08X}, shell-scoped: 0x{:08X}..=0x{:08X}",
            kind.label(),
            type_code,
            core_lo,
            core_hi,
            shell_lo,
            shell_hi,
        ),
    ))
}

fn named_fields<'a>(data: &'a Data, name: &Ident) -> syn::Result<&'a Punctuated<Field, Token![,]>> {
    match data {
        Data::Struct(DataStruct {
            fields: Fields::Named(f),
            ..
        }) => Ok(&f.named),
        _ => Err(syn::Error::new(
            name.span(),
            "arkhe-forge-macros derives require a struct with named fields",
        )),
    }
}

fn validate_schema_version_first_field(data: &Data, name: &Ident) -> syn::Result<()> {
    let fields = named_fields(data, name)?;
    let first = fields.first().ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "struct must have `schema_version: u16` as its first field",
        )
    })?;
    let ident = first.ident.as_ref().ok_or_else(|| {
        syn::Error::new(first.span(), "first field must be named `schema_version`")
    })?;
    if ident != "schema_version" {
        return Err(syn::Error::new(
            ident.span(),
            format!(
                "first field must be named `schema_version`, got `{}`",
                ident
            ),
        ));
    }
    if !is_u16(&first.ty) {
        return Err(syn::Error::new(
            first.ty.span(),
            "`schema_version` field must be of type `u16`",
        ));
    }
    Ok(())
}

fn is_u16(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if tp.qself.is_none() {
            if let Some(seg) = tp.path.segments.last() {
                return seg.ident == "u16" && seg.arguments.is_empty();
            }
        }
    }
    false
}

fn validate_band(band: u8, name: &Ident) -> syn::Result<()> {
    if (1..=3).contains(&band) {
        return Ok(());
    }
    Err(syn::Error::new(
        name.span(),
        format!(
            "ArkheAction band must be 1 (Core), 2 (Projection), or 3 (Protocol); got {}",
            band
        ),
    ))
}

fn validate_idempotency_key_field(data: &Data, name: &Ident) -> syn::Result<()> {
    let fields = named_fields(data, name)?;
    for field in fields {
        let Some(ident) = &field.ident else {
            continue;
        };
        if ident != "idempotency_key" {
            continue;
        }
        if !is_option_byte_array_16(&field.ty) {
            return Err(syn::Error::new(
                field.ty.span(),
                "`idempotency_key` field must have the exact type `Option<[u8; 16]>`",
            ));
        }
        return Ok(());
    }
    Err(syn::Error::new(
        name.span(),
        "#[arkhe(idempotent)] requires field `idempotency_key: Option<[u8; 16]>`",
    ))
}

/// Match `Option<[u8; 16]>` — last path segment `Option`, single angle-bracketed
/// generic argument that is `[u8; 16]`. Rejects fully-qualified path forms
/// (`std::option::Option<...>`) since the canonical Rust prelude exposes
/// `Option` unqualified — derive consumers should follow suit.
fn is_option_byte_array_16(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    if tp.qself.is_some() {
        return false;
    }
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident != "Option" {
        return false;
    }
    let PathArguments::AngleBracketed(generic) = &seg.arguments else {
        return false;
    };
    if generic.args.len() != 1 {
        return false;
    }
    let GenericArgument::Type(inner) = &generic.args[0] else {
        return false;
    };
    is_byte_array_16(inner)
}

fn is_byte_array_16(ty: &Type) -> bool {
    let Type::Array(TypeArray { elem, len, .. }) = ty else {
        return false;
    };
    if !is_u8(elem) {
        return false;
    }
    let Expr::Lit(lit) = len else {
        return false;
    };
    let Lit::Int(int) = &lit.lit else {
        return false;
    };
    int.base10_parse::<usize>().is_ok_and(|n| n == 16)
}

fn is_u8(ty: &Type) -> bool {
    let Type::Path(tp) = ty else {
        return false;
    };
    if tp.qself.is_some() {
        return false;
    }
    tp.path
        .segments
        .last()
        .is_some_and(|s| s.ident == "u8" && s.arguments.is_empty())
}

fn validate_canonical_sort_fields(data: &Data) -> syn::Result<()> {
    let fields = match data {
        Data::Struct(DataStruct {
            fields: Fields::Named(f),
            ..
        }) => &f.named,
        _ => return Ok(()),
    };
    for field in fields {
        let field_attrs = FieldAttrs::from_field(field)
            .map_err(|e| syn::Error::new(field.span(), e.to_string()))?;
        if field_attrs.canonical_sort && !is_vec_or_btreeset(&field.ty) {
            return Err(syn::Error::new(
                field.ty.span(),
                "#[arkhe(canonical_sort)] is allowed only on `Vec<T>` or `BTreeSet<T>` fields",
            ));
        }
    }
    Ok(())
}

fn is_vec_or_btreeset(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if tp.qself.is_none() {
            if let Some(seg) = tp.path.segments.last() {
                return seg.ident == "Vec" || seg.ident == "BTreeSet";
            }
        }
    }
    false
}
