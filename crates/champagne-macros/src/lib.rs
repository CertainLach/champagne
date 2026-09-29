use proc_macro2::{Delimiter, Group, TokenStream};
use quote::{ToTokens, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Ident, LitStr, ReturnType, Token, Type, Visibility, parenthesized, token};

mod kw {
	syn::custom_keyword!(alias);
	syn::custom_keyword!(no_instrument);
	syn::custom_keyword!(no_reset_last_error);
}

struct Param {
	mut_: Option<Token![mut]>,
	name: Ident,
	colon: Token![:],
	ty: Type,
}

impl Parse for Param {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		Ok(Self {
			mut_: input.parse()?,
			name: input.parse()?,
			colon: input.parse()?,
			ty: input.parse()?,
		})
	}
}

impl ToTokens for Param {
	fn to_tokens(&self, tokens: &mut TokenStream) {
		self.mut_.to_tokens(tokens);
		self.name.to_tokens(tokens);
		self.colon.to_tokens(tokens);
		self.ty.to_tokens(tokens);
	}
}

struct WinFnArgs {
	aliases: Vec<Ident>,
	no_instrument: bool,
	no_reset_last_error: bool,
}

impl Parse for WinFnArgs {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		let mut aliases = Vec::new();
		let mut no_instrument = false;
		let mut no_reset_last_error = false;
		while !input.is_empty() {
			if input.peek(kw::alias) {
				let _: kw::alias = input.parse()?;
				let content;
				parenthesized!(content in input);
				aliases.extend(content.parse_terminated(Ident::parse, Token![,])?);
			} else if input.peek(kw::no_instrument) {
				let _: kw::no_instrument = input.parse()?;
				no_instrument = true;
			} else if input.peek(kw::no_reset_last_error) {
				let _: kw::no_reset_last_error = input.parse()?;
				no_reset_last_error = true;
			} else {
				return Err(
					input.error("expected `alias`, `no_instrument`, or `no_reset_last_error`")
				);
			}
			if !input.is_empty() {
				let _: Token![,] = input.parse()?;
			}
		}
		Ok(Self {
			aliases,
			no_instrument,
			no_reset_last_error,
		})
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
	no_instrument: bool,
}

impl WinFn {
	fn parse_with_args(input: ParseStream, macro_args: &WinFnArgs) -> syn::Result<Self> {
		let mut attrs = Vec::new();
		let mut naked = false;
		for attr in Attribute::parse_outer(input)? {
			if attr.path().is_ident("naked") {
				naked = true;
			} else if attr.path().is_ident("unsafe")
				&& attr.to_token_stream().to_string().contains("naked")
			{
				naked = true;
			}
			attrs.push(attr);
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
			macro_args
				.aliases
				.iter()
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
			no_instrument: macro_args.no_instrument || naked,
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
			no_instrument,
			..
		} = self;
		let mut params = TokenStream::new();
		self.paren
			.surround(&mut params, |t| self.params.to_tokens(t));
		let body_inner = body.stream();
		let emit_body = if *no_instrument {
			quote! { { #body_inner } }
		} else {
			quote! { { tracing::trace!("call"); #body_inner } }
		};
		let instrument = if *no_instrument {
			quote! {}
		} else {
			quote! { #[crate::instrument(level="trace", ret(level = "trace"))] }
		};
		tokens.extend(quote! {
			#(#attrs)*
			#[allow(non_snake_case)]
			#instrument
			#vis #unsafety extern "win64" #fn_token #ident #params #output #emit_body
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

#[proc_macro_attribute]
pub fn winfn(
	attr: proc_macro::TokenStream,
	input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
	let args = syn::parse_macro_input!(attr as WinFnArgs);
	let input2: TokenStream = input.into();
	let parsed = match syn::parse::Parser::parse2(
		|stream: ParseStream| {
			let mut fns = Vec::new();
			while !stream.is_empty() {
				fns.push(WinFn::parse_with_args(stream, &args)?);
			}
			Ok(fns)
		},
		input2,
	) {
		Ok(fns) => fns,
		Err(e) => return e.to_compile_error().into(),
	};
	quote!(#(#parsed)*).into()
}
