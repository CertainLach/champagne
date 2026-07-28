use proc_macro2::{Delimiter, Group, TokenStream};
use quote::{ToTokens, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Ident, LitStr, ReturnType, Token, Type, Visibility, parenthesized, token};

struct Param {
	name: Ident,
	colon: Token![:],
	ty: Type,
}

impl Parse for Param {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		Ok(Self {
			name: input.parse()?,
			colon: input.parse()?,
			ty: input.parse()?,
		})
	}
}

impl ToTokens for Param {
	fn to_tokens(&self, tokens: &mut TokenStream) {
		self.name.to_tokens(tokens);
		self.colon.to_tokens(tokens);
		self.ty.to_tokens(tokens);
	}
}

struct WinFn {
	attrs: Vec<Attribute>,
	names: Vec<LitStr>,
	vis: Visibility,
	unsafety: Option<Token![unsafe]>,
	fn_token: Token![fn],
	ident: Ident,
	paren: token::Paren,
	params: Punctuated<Param, Token![,]>,
	output: ReturnType,
	body: Group,
}

impl Parse for WinFn {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		let mut attrs = Vec::new();
		let mut aliases = Vec::new();
		for attr in Attribute::parse_outer(input)? {
			if attr.path().is_ident("alias") {
				aliases.extend(
					attr.parse_args_with(Punctuated::<Ident, Token![,]>::parse_terminated)?,
				);
			} else {
				attrs.push(attr);
			}
		}
		let vis = input.parse()?;
		let unsafety = input.parse()?;
		let fn_token = input.parse()?;
		let ident: Ident = input.parse()?;
		let content;
		let paren = parenthesized!(content in input);
		let params = content.parse_terminated(Param::parse, Token![,])?;
		let output = input.parse()?;
		let body: Group = input.parse()?;
		if body.delimiter() != Delimiter::Brace {
			return Err(syn::Error::new(body.span(), "expected `{ .. }` body"));
		}
		let mut names = vec![LitStr::new(&ident.to_string(), ident.span())];
		names.extend(
			aliases
				.into_iter()
				.map(|i| LitStr::new(&i.to_string(), i.span())),
		);
		Ok(Self {
			attrs,
			names,
			vis,
			unsafety,
			fn_token,
			ident,
			paren,
			params,
			output,
			body,
		})
	}
}

impl ToTokens for WinFn {
	fn to_tokens(&self, tokens: &mut TokenStream) {
		let Self {
			attrs,
			names,
			vis,
			unsafety,
			fn_token,
			ident,
			output,
			body,
			..
		} = self;
		let mut params = TokenStream::new();
		self.paren
			.surround(&mut params, |t| self.params.to_tokens(t));
		tokens.extend(quote! {
			#(#attrs)*
			#[allow(non_snake_case)]
			#vis #unsafety extern "win64" #fn_token #ident #params #output #body
		});
		let cfgs: Vec<&Attribute> = attrs.iter().filter(|a| a.path().is_ident("cfg")).collect();
		for name in names {
			tokens.extend(quote! {
				#(#cfgs)*
				::champagne_winapi::inventory::submit! {
					::champagne_winapi::WinFn { name: #name, ptr: || #ident as *const () as usize }
				}
			});
		}
	}
}

struct Batch(Vec<WinFn>);

impl Parse for Batch {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		let mut fns = Vec::new();
		while !input.is_empty() {
			fns.push(input.parse()?);
		}
		Ok(Self(fns))
	}
}

#[proc_macro_attribute]
pub fn winfn(
	attr: proc_macro::TokenStream,
	input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
	let fns = syn::parse_macro_input!(input as Batch).0;
	quote!(#(#fns)*).into()
}
