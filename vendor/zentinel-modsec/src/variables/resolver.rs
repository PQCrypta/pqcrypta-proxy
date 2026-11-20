//! Variable resolution engine.

use super::{RequestData, ResponseData, TxCollection};
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

/// Compile a regex written in rule text (an `ARGS:/.../` selection or a
/// `!ARGS:/.../` exclusion), once per pattern.
///
/// These used to be compiled on every evaluation, once per resolved key for an
/// exclusion. Compiling costs orders of magnitude more than matching: CRS
/// 942431's two `!ARGS_NAMES:/.../` exclusions took ~5.5ms per request on
/// clean traffic, for patterns that never change.
///
/// Patterns come only from loaded rules, so the cache is bounded by the rule
/// set. A pattern that does not compile is cached as `None` and never matches,
/// as before. `Regex` clones share the compiled program.
fn cached_regex(pattern: &str) -> Option<Regex> {
    static CACHE: Lazy<RwLock<HashMap<String, Option<Regex>>>> = Lazy::new(Default::default);
    if let Some(hit) = CACHE.read().unwrap_or_else(|e| e.into_inner()).get(pattern) {
        return hit.clone();
    }
    // Case-insensitive, as a key selection is: collection keys are, in
    // ModSecurity, and TX keys are stored lowercased, so CRS's 922110 reading
    // `TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/` found none of the keys its
    // 922150 sets
    let compiled = regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .ok();
    CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .entry(pattern.to_string())
        .or_insert(compiled)
        .clone()
}

/// Variable resolver for transaction context.
pub struct VariableResolver<'a> {
    request: &'a RequestData,
    response: &'a ResponseData,
    tx: &'a TxCollection,
    matched_var: Option<&'a str>,
    matched_vars: &'a [(String, String)],
    /// Carried alongside the other resolver inputs for symmetry; no variable
    /// reads it yet (`TX:0`..`TX:9` are served from the TX collection).
    #[allow(dead_code)]
    captures: &'a [String],
}

impl<'a> VariableResolver<'a> {
    /// Create a new resolver.
    pub fn new(
        request: &'a RequestData,
        response: &'a ResponseData,
        tx: &'a TxCollection,
        matched_var: Option<&'a str>,
        matched_vars: &'a [(String, String)],
        captures: &'a [String],
    ) -> Self {
        Self {
            request,
            response,
            tx,
            matched_var,
            matched_vars,
            captures,
        }
    }

    /// Resolve a variable specification to values.
    pub fn resolve(&self, spec: &VariableSpec) -> Vec<(String, String)> {
        let values = self.resolve_variable(spec.name, &spec.selection);

        // Apply exclusions
        if spec.exclusions.is_empty() {
            values
        } else {
            values
                .into_iter()
                .filter(|(k, _)| !spec.exclusions.iter().any(|e| exclusion_matches(k, e)))
                .collect()
        }
    }

    /// Resolve a variable by name.
    fn resolve_variable(
        &self,
        name: VariableName,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        match name {
            // Request variables
            VariableName::RequestUri => {
                vec![("REQUEST_URI".to_string(), self.request.uri.clone())]
            }
            VariableName::RequestUriRaw => {
                vec![("REQUEST_URI_RAW".to_string(), self.request.uri_raw.clone())]
            }
            VariableName::RequestMethod => {
                vec![("REQUEST_METHOD".to_string(), self.request.method.clone())]
            }
            VariableName::RequestProtocol => {
                vec![(
                    "REQUEST_PROTOCOL".to_string(),
                    self.request.protocol.clone(),
                )]
            }
            VariableName::QueryString => {
                vec![(
                    "QUERY_STRING".to_string(),
                    self.request.query_string.clone(),
                )]
            }
            VariableName::RequestFilename => {
                vec![("REQUEST_FILENAME".to_string(), self.request.path.clone())]
            }
            VariableName::RequestLine => {
                // The request line as it arrived. CRS 920100 tests this with a
                // negated regex, so leaving it unresolved made that rule match
                // every request rather than none.
                let uri = if self.request.uri_raw.is_empty() {
                    &self.request.uri
                } else {
                    &self.request.uri_raw
                };
                vec![(
                    "REQUEST_LINE".to_string(),
                    format!("{} {} {}", self.request.method, uri, self.request.protocol),
                )]
            }
            VariableName::RequestBasename => {
                // Final path segment. ModSecurity splits on both separators, so
                // a Windows-style path does not hide the basename.
                let basename = self
                    .request
                    .path
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                vec![("REQUEST_BASENAME".to_string(), basename)]
            }
            VariableName::ArgsCombinedSize => {
                use super::collection::Collection;
                let size: usize = [&self.request.args_get, &self.request.args_post]
                    .iter()
                    .flat_map(|c| c.all())
                    .map(|(name, value)| name.len() + value.len())
                    .sum();
                vec![("ARGS_COMBINED_SIZE".to_string(), size.to_string())]
            }
            // REQUEST_BODY: the raw body after the URLENCODED or JSON processor,
            // or when ctl:forceRequestBodyVariable=On (CRS 901340, for a body
            // no processor parses); see RequestData::request_body_variable.
            VariableName::RequestBody => {
                if self.request.request_body_variable() {
                    vec![("REQUEST_BODY".to_string(), self.request.body_str())]
                } else {
                    vec![]
                }
            }
            VariableName::UniqueId => {
                vec![("UNIQUE_ID".to_string(), self.request.unique_id.clone())]
            }
            VariableName::RequestBodyLength => {
                vec![(
                    "REQUEST_BODY_LENGTH".to_string(),
                    self.request.body_length().to_string(),
                )]
            }

            // Collections
            VariableName::Args => self.resolve_collection_from_all_args(selection),
            VariableName::ArgsGet => {
                self.resolve_collection(&self.request.args_get, "ARGS_GET", selection)
            }
            VariableName::ArgsPost => {
                self.resolve_collection(&self.request.args_post, "ARGS_POST", selection)
            }
            VariableName::ArgsNames => self.resolve_collection_names(
                &[&self.request.args_get, &self.request.args_post],
                "ARGS_NAMES",
                selection,
            ),
            VariableName::ArgsGetNames => self.resolve_collection_names(
                &[&self.request.args_get],
                "ARGS_GET_NAMES",
                selection,
            ),
            VariableName::ArgsPostNames => self.resolve_collection_names(
                &[&self.request.args_post],
                "ARGS_POST_NAMES",
                selection,
            ),
            VariableName::RequestHeaders => {
                self.resolve_collection_ci(&self.request.headers, "REQUEST_HEADERS", selection)
            }
            VariableName::RequestHeadersNames => self.resolve_collection_names(
                &[&self.request.headers],
                "REQUEST_HEADERS_NAMES",
                selection,
            ),
            VariableName::RequestCookies => {
                self.resolve_collection(&self.request.cookies, "REQUEST_COOKIES", selection)
            }
            VariableName::RequestCookiesNames => self.resolve_collection_names(
                &[&self.request.cookies],
                "REQUEST_COOKIES_NAMES",
                selection,
            ),

            // Multipart body processor results
            VariableName::MultipartPartHeaders => self.resolve_collection(
                &self.request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                selection,
            ),
            VariableName::Files => self.resolve_collection(&self.request.files, "FILES", selection),
            VariableName::FilesNames => {
                self.resolve_collection_names(&[&self.request.files], "FILES_NAMES", selection)
            }
            VariableName::FilesSizes => {
                self.resolve_collection(&self.request.files_sizes, "FILES_SIZES", selection)
            }
            VariableName::FilesCombinedSize => vec![(
                "FILES_COMBINED_SIZE".to_string(),
                self.request.files_combined_size.to_string(),
            )],

            // The multipart processor's findings (variables::multipart):
            // absent when it did not run, 0 or 1 when it did
            VariableName::MultipartStrictError => {
                self.multipart_flag("MULTIPART_STRICT_ERROR", |f| f.strict_error().into())
            }
            VariableName::MultipartBoundaryQuoted => {
                self.multipart_flag("MULTIPART_BOUNDARY_QUOTED", |f| f.boundary_quoted.into())
            }
            VariableName::MultipartBoundaryWhitespace => self
                .multipart_flag("MULTIPART_BOUNDARY_WHITESPACE", |f| {
                    f.boundary_whitespace.into()
                }),
            VariableName::MultipartDataBefore => {
                self.multipart_flag("MULTIPART_DATA_BEFORE", |f| f.data_before.into())
            }
            VariableName::MultipartDataAfter => {
                self.multipart_flag("MULTIPART_DATA_AFTER", |f| f.data_after.into())
            }
            VariableName::MultipartHeaderFolding => {
                self.multipart_flag("MULTIPART_HEADER_FOLDING", |f| f.header_folding.into())
            }
            VariableName::MultipartInvalidHeaderFolding => self
                .multipart_flag("MULTIPART_INVALID_HEADER_FOLDING", |f| {
                    f.invalid_header_folding.into()
                }),
            VariableName::MultipartLfLine => {
                self.multipart_flag("MULTIPART_LF_LINE", |f| f.lf_line.into())
            }
            VariableName::MultipartCrlfLfLines => self
                .multipart_flag("MULTIPART_CRLF_LF_LINES", |f| {
                    (f.crlf_line && f.lf_line).into()
                }),
            VariableName::MultipartMissingSemicolon => self
                .multipart_flag("MULTIPART_MISSING_SEMICOLON", |f| {
                    f.missing_semicolon.into()
                }),
            VariableName::MultipartInvalidQuoting => {
                self.multipart_flag("MULTIPART_INVALID_QUOTING", |f| f.invalid_quoting.into())
            }
            VariableName::MultipartInvalidPart => {
                self.multipart_flag("MULTIPART_INVALID_PART", |f| f.invalid_part.into())
            }
            VariableName::MultipartFileLimitExceeded => self
                .multipart_flag("MULTIPART_FILE_LIMIT_EXCEEDED", |f| {
                    f.file_limit_exceeded.into()
                }),
            VariableName::MultipartUnmatchedBoundary => {
                self.multipart_flag("MULTIPART_UNMATCHED_BOUNDARY", |f| f.unmatched_boundary)
            }
            // Present, empty, when no processor applies, as in ModSecurity:
            // CRS's 901340 (`!@rx (?:URLENCODED|MULTIPART|XML|JSON)`) forces
            // REQUEST_BODY for exactly that body, and a negated operator does
            // not match an absent variable.
            VariableName::ReqBodyProcessor => vec![(
                "REQBODY_PROCESSOR".to_string(),
                self.request.body_processor.clone(),
            )],

            // A body the processor could not handle. These resolved to nothing
            // before, so CRS rule 200002 (`SecRule REQBODY_ERROR "!@eq 0"`)
            // could never fire and a rejected body passed unexamined and
            // unreported.
            //
            // REQBODY_ERROR always has a value -- "0" when the body processed
            // cleanly -- because a rule comparing it against 0 must be able to
            // find it. REQBODY_ERROR_MSG is absent unless there is a message,
            // matching ModSecurity.
            VariableName::ReqBodyError | VariableName::ReqBodyProcessorError => {
                let flag = if self.request.body_error.is_some() {
                    "1"
                } else {
                    "0"
                };
                vec![("REQBODY_ERROR".to_string(), flag.to_string())]
            }
            VariableName::ReqBodyErrorMsg | VariableName::ReqBodyProcessorErrorMsg => {
                match &self.request.body_error {
                    Some(msg) => vec![("REQBODY_ERROR_MSG".to_string(), msg.clone())],
                    None => vec![],
                }
            }

            // Response variables
            VariableName::ResponseStatus => {
                vec![(
                    "RESPONSE_STATUS".to_string(),
                    self.response.status.to_string(),
                )]
            }
            VariableName::ResponseBody => {
                vec![("RESPONSE_BODY".to_string(), self.response.body_str())]
            }
            VariableName::ResponseContentType => {
                vec![(
                    "RESPONSE_CONTENT_TYPE".to_string(),
                    self.response.content_type.clone(),
                )]
            }
            VariableName::ResponseHeaders => {
                self.resolve_collection_ci(&self.response.headers, "RESPONSE_HEADERS", selection)
            }

            // TX collection
            VariableName::Xml => self.resolve_xml(selection),

            VariableName::Tx => self.resolve_tx_collection(selection),

            // Client/Server info
            VariableName::RemoteAddr => {
                vec![("REMOTE_ADDR".to_string(), self.request.client_ip.clone())]
            }
            VariableName::RemotePort => {
                vec![(
                    "REMOTE_PORT".to_string(),
                    self.request.client_port.to_string(),
                )]
            }
            VariableName::ServerName => {
                vec![("SERVER_NAME".to_string(), self.request.server_name.clone())]
            }
            VariableName::ServerAddr => {
                vec![("SERVER_ADDR".to_string(), self.request.server_addr.clone())]
            }
            VariableName::ServerPort => {
                vec![(
                    "SERVER_PORT".to_string(),
                    self.request.server_port.to_string(),
                )]
            }

            // Matched variables
            VariableName::MatchedVar => {
                if let Some(v) = self.matched_var {
                    vec![("MATCHED_VAR".to_string(), v.to_string())]
                } else {
                    vec![]
                }
            }
            VariableName::MatchedVars => self
                .matched_vars
                .iter()
                .map(|(k, v)| (format!("MATCHED_VARS:{}", k), v.clone()))
                .collect(),
            VariableName::MatchedVarName => match self.matched_vars.last() {
                Some((name, _)) => vec![("MATCHED_VAR_NAME".to_string(), name.clone())],
                None => vec![],
            },
            VariableName::MatchedVarsNames => self
                .matched_vars
                .iter()
                .map(|(k, _)| (format!("MATCHED_VARS_NAMES:{}", k), k.clone()))
                .collect(),

            // Default - empty
            _ => vec![],
        }
    }

    /// Resolve a collection with optional selection.
    fn resolve_collection(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        self.resolve_collection_inner(collection, prefix, selection, false)
    }

    /// Resolve a collection where keys are matched case-insensitively (HTTP headers).
    fn resolve_collection_ci(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        self.resolve_collection_inner(collection, prefix, selection, true)
    }

    fn resolve_collection_inner(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
        lowercase_key: bool,
    ) -> Vec<(String, String)> {
        use super::collection::Collection;

        match selection {
            Some(Selection::Key(key)) => {
                let lookup = if lowercase_key {
                    key.to_ascii_lowercase()
                } else {
                    key.clone()
                };
                if let Some(values) = collection.get(&lookup) {
                    values
                        .into_iter()
                        .map(|v| (format!("{}:{}", prefix, key), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Some(re) = cached_regex(pattern) {
                    collection
                        .get_regex(&re)
                        .into_iter()
                        .map(|(k, v)| (format!("{}:{}", prefix, k), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            None => collection
                .all()
                .into_iter()
                .map(|(k, v)| (format!("{}:{}", prefix, k), v.to_string()))
                .collect(),
        }
    }

    /// Resolve ARGS collection (GET + POST combined).
    /// Resolve an `XML:` target against the flattened XML body.
    ///
    /// The XML body processor flattens element text to `xml.<path>` and
    /// attributes to `xml.<path>.@<name>` in the XML collection (not ARGS,
    /// as in ModSecurity). `XML:/*` and `XML://@*`
    /// are exactly those two sets, so they are answered from the flattening
    /// rather than by evaluating XPath.
    ///
    /// Values are reported under their XPath-style name -- `xml.order.item.@id`
    /// is reported as `XML:/order/item/@id` -- so `%{MATCHED_VAR_NAME}` in a
    /// rule's `logdata` names the node the way the rule addressed it.
    /// One `MULTIPART_*` variable: absent when the multipart processor did
    /// not run.
    fn multipart_flag(
        &self,
        name: &str,
        get: impl Fn(&super::multipart::MultipartFlags) -> u8,
    ) -> Vec<(String, String)> {
        self.request
            .multipart
            .as_ref()
            .map(|f| vec![(name.to_string(), get(f).to_string())])
            .unwrap_or_default()
    }

    fn resolve_xml(&self, selection: &Option<Selection>) -> Vec<(String, String)> {
        use super::collection::Collection;

        let Some(target) = XmlTarget::from_selection(selection.as_ref()) else {
            // An XPath expression this engine cannot express. Reported when the
            // rules load, so there is nothing to say per request.
            return vec![];
        };

        self.request
            .xml
            .all()
            .into_iter()
            .filter_map(|(name, value)| {
                let path = name.strip_prefix("xml.")?;
                // An XML element name cannot begin with `@`, so `.@` only ever
                // marks the attribute segment this processor appends.
                let is_attribute = path.contains(".@");
                let wanted = match target {
                    XmlTarget::Elements => !is_attribute,
                    XmlTarget::Attributes => is_attribute,
                    XmlTarget::All => true,
                };
                if !wanted {
                    return None;
                }
                Some((
                    format!("XML:/{}", path.replace('.', "/")),
                    value.to_string(),
                ))
            })
            .collect()
    }

    fn resolve_collection_from_all_args(
        &self,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        let mut result = self.resolve_collection(&self.request.args_get, "ARGS", selection);
        result.extend(self.resolve_collection(&self.request.args_post, "ARGS", selection));
        result
    }

    /// Resolve a `*_NAMES` collection: the values are the keys of the backing
    /// collection(s), one entry per stored value (duplicates preserved,
    /// matching ModSecurity).
    fn resolve_collection_names(
        &self,
        collections: &[&super::collection::HashMapCollection],
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vec<(String, String)> {
        use super::collection::Collection;

        let mut result = Vec::new();
        for collection in collections {
            for (key, _) in collection.all() {
                let selected = match selection {
                    Some(Selection::Key(sel)) => key.eq_ignore_ascii_case(sel),
                    Some(Selection::Regex(pattern)) => cached_regex(pattern)
                        .map(|re| re.is_match(key))
                        .unwrap_or(false),
                    None => true,
                };
                if selected {
                    result.push((format!("{}:{}", prefix, key), key.to_string()));
                }
            }
        }
        result
    }

    /// Resolve TX collection.
    fn resolve_tx_collection(&self, selection: &Option<Selection>) -> Vec<(String, String)> {
        use super::collection::Collection;

        match selection {
            Some(Selection::Key(key)) => {
                if let Some(values) = self.tx.get(key) {
                    values
                        .into_iter()
                        .map(|v| (format!("TX:{}", key), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Some(re) = cached_regex(pattern) {
                    self.tx
                        .get_regex(&re)
                        .into_iter()
                        .map(|(k, v)| (format!("TX:{}", k), v.to_string()))
                        .collect()
                } else {
                    vec![]
                }
            }
            None => self
                .tx
                .all()
                .into_iter()
                .map(|(k, v)| (format!("TX:{}", k), v.to_string()))
                .collect(),
        }
    }
}

/// Check whether a resolved variable key (e.g. `ARGS:password`) is excluded by
/// a target exclusion (`!TARGET` in a rule's variable list or in
/// `SecRuleUpdateTargetById`).
///
/// Supported exclusion forms, per ModSecurity:
/// - `COLLECTION:key` — excludes that member (key compared case-insensitively);
/// - `COLLECTION:/regex/` — excludes members whose key matches the regex;
/// - `COLLECTION` — excludes the entire collection.
fn exclusion_matches(key: &str, exclusion: &str) -> bool {
    match exclusion.split_once(':') {
        Some((excl_coll, excl_sel)) => {
            let Some((key_coll, key_member)) = key.split_once(':') else {
                return false;
            };
            if !key_coll.eq_ignore_ascii_case(excl_coll) {
                return false;
            }
            if excl_sel.len() > 2 && excl_sel.starts_with('/') && excl_sel.ends_with('/') {
                cached_regex(&excl_sel[1..excl_sel.len() - 1])
                    .map(|re| re.is_match(key_member))
                    .unwrap_or(false)
            } else {
                key_member.eq_ignore_ascii_case(excl_sel)
            }
        }
        None => {
            let key_coll = key.split_once(':').map(|(c, _)| c).unwrap_or(key);
            key_coll.eq_ignore_ascii_case(exclusion)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{cached_regex, exclusion_matches};

    #[test]
    fn test_cached_regex_compiles_once_and_keeps_invalid_patterns_dead() {
        let a = cached_regex(r"^user_\d+$").expect("valid pattern");
        let b = cached_regex(r"^user_\d+$").expect("valid pattern");
        assert!(a.is_match("user_42") && b.is_match("user_42"));
        // An invalid pattern stays a never-matching selection, cached or not.
        assert!(cached_regex("(unclosed").is_none());
        assert!(cached_regex("(unclosed").is_none());
        assert!(!exclusion_matches("ARGS:x", "ARGS:/(unclosed/"));
    }

    #[test]
    fn test_exclusion_exact_key() {
        assert!(exclusion_matches("ARGS:password", "ARGS:password"));
        assert!(exclusion_matches("ARGS:Password", "ARGS:password"));
        // Must NOT be a prefix/substring match.
        assert!(!exclusion_matches("ARGS:password2", "ARGS:password"));
        assert!(!exclusion_matches("ARGS:xpassword", "ARGS:password"));
        // Different collection.
        assert!(!exclusion_matches(
            "REQUEST_COOKIES:password",
            "ARGS:password"
        ));
    }

    #[test]
    fn test_exclusion_regex_key() {
        // CRS pattern: SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga_ABC123",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(exclusion_matches(
            "REQUEST_COOKIES:_ga",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(!exclusion_matches(
            "REQUEST_COOKIES:session",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
    }

    #[test]
    fn test_exclusion_whole_collection() {
        assert!(exclusion_matches("ARGS:anything", "ARGS"));
        assert!(!exclusion_matches("ARGS_NAMES:anything", "ARGS"));
    }
}
