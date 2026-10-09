//! The request path every listener routes and forwards on.
//!
//! A path can name the same resource many ways: `/a//b`, `/a/./b`,
//! `/x/../a/b`, `/a/%2e/b`. Routing on the raw form lets one of those miss a
//! route that guards the canonical one (a deny, an mTLS gate, a redirect) while
//! the origin, which resolves them, serves the resource anyway. Every listener
//! therefore routes and forwards on one canonical form, built here:
//!
//! - **dot segments** are removed as RFC 3986 §5.2.4 describes, including the
//!   percent-encoded forms (`%2e`, `.%2E`), which §6.2.2.2 says decode to the
//!   same unreserved character (`resolve_dot_segments`, default on);
//! - **repeated slashes** collapse to one (`merge_slashes`, default on), as
//!   Apache's `MergeSlashes` does at the origin;
//! - **case** is folded to ASCII lowercase when `normalize_paths` is on.
//!
//! The WAF does not see this form: it inspects the raw request, so a
//! traversal attempt is still detected, logged and scored as one. HMAC
//! proof-of-possession also signs the raw `path_and_query`, which is what the
//! client sent.

use std::borrow::Cow;

use crate::config::ServerConfig;

/// Which canonicalisations apply, from `[server]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCanon {
    pub resolve_dot_segments: bool,
    pub merge_slashes: bool,
    pub lowercase: bool,
}

impl From<&ServerConfig> for PathCanon {
    fn from(server: &ServerConfig) -> Self {
        Self {
            resolve_dot_segments: server.resolve_dot_segments,
            merge_slashes: server.merge_slashes,
            lowercase: server.normalize_paths,
        }
    }
}

/// `.` or `..`, literally or percent-encoded, else `None`.
fn dot_segment(segment: &str) -> Option<DotSegment> {
    let bytes = segment.as_bytes();
    let mut dots = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            i += 1;
        } else if bytes[i] == b'%'
            && bytes.get(i + 1) == Some(&b'2')
            && matches!(bytes.get(i + 2), Some(b'e' | b'E'))
        {
            i += 3;
        } else {
            return None;
        }
        dots += 1;
        if dots > 2 {
            return None;
        }
    }
    match dots {
        1 => Some(DotSegment::Current),
        2 => Some(DotSegment::Parent),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotSegment {
    Current,
    Parent,
}

/// Whether `raw` needs any structural change: a cheap scan so the common,
/// already-canonical path is borrowed rather than rebuilt.
fn needs_structure(raw: &str, canon: PathCanon) -> bool {
    (canon.merge_slashes && raw.contains("//"))
        || (canon.resolve_dot_segments && raw.split('/').any(|s| dot_segment(s).is_some()))
}

/// The canonical form of an origin-form request path. Anything that is not
/// an absolute path (`*`, an empty path) is returned unchanged.
pub fn canonical_path(raw: &str, canon: PathCanon) -> Cow<'_, str> {
    let structural = raw.starts_with('/') && needs_structure(raw, canon);
    let fold = canon.lowercase && raw.bytes().any(|b| b.is_ascii_uppercase());
    if !structural && !fold {
        return Cow::Borrowed(raw);
    }

    let mut path = if structural {
        let pieces: Vec<&str> = raw[1..].split('/').collect();
        let last = pieces.len() - 1;
        let mut out: Vec<&str> = Vec::with_capacity(pieces.len());
        for (i, segment) in pieces.into_iter().enumerate() {
            let is_last = i == last;
            match canon
                .resolve_dot_segments
                .then(|| dot_segment(segment))
                .flatten()
            {
                Some(DotSegment::Current) => {
                    // "/a/." names the directory: keep its trailing slash
                    if is_last {
                        out.push("");
                    }
                }
                Some(DotSegment::Parent) => {
                    // Above the root there is nothing to remove. An empty
                    // segment kept with merge_slashes off is a level, as in
                    // RFC 3986: "/a//.." is "/a/"
                    out.pop();
                    if is_last {
                        out.push("");
                    }
                }
                None if segment.is_empty() && canon.merge_slashes && !is_last => {}
                None => out.push(segment),
            }
        }
        let mut path = String::with_capacity(raw.len());
        path.push('/');
        // A trailing "" from "/a/" or "/a/." joins as the trailing slash; on
        // its own (everything resolved away) it is just the root
        if !(out.len() == 1 && out[0].is_empty()) {
            path.push_str(&out.join("/"));
        }
        path
    } else {
        raw.to_string()
    };
    if fold {
        path.make_ascii_lowercase();
    }
    Cow::Owned(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: PathCanon = PathCanon {
        resolve_dot_segments: true,
        merge_slashes: true,
        lowercase: false,
    };

    fn canon(raw: &str) -> String {
        canonical_path(raw, ALL).into_owned()
    }

    #[test]
    fn a_canonical_path_is_borrowed_unchanged() {
        for raw in [
            "/",
            "/a",
            "/a/b/",
            "/fun/fractaltree/",
            "/a.b/c..d/.e",
            "*",
            "",
        ] {
            assert!(
                matches!(canonical_path(raw, ALL), Cow::Borrowed(_)),
                "{raw} should be borrowed"
            );
            assert_eq!(canon(raw), raw);
        }
    }

    #[test]
    fn dot_segments_resolve_as_rfc_3986_says() {
        // RFC 3986 §5.2.4 and §5.4's normal examples, as absolute paths
        assert_eq!(canon("/a/b/c/./../../g"), "/a/g");
        assert_eq!(canon("/mid/content=5/../6"), "/mid/6");
        assert_eq!(canon("/a/./b"), "/a/b");
        assert_eq!(canon("/a/b/.."), "/a/");
        assert_eq!(canon("/a/b/."), "/a/b/");
        assert_eq!(canon("/./dev/"), "/dev/");
        assert_eq!(canon("/fun/../dev/"), "/dev/");
        assert_eq!(canon("/.."), "/");
        assert_eq!(canon("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(canon("/a/b/../"), "/a/");
    }

    #[test]
    fn percent_encoded_dots_are_dots() {
        assert_eq!(canon("/%2e/dev/"), "/dev/");
        assert_eq!(canon("/x/%2E%2e/dev/"), "/dev/");
        assert_eq!(canon("/x/.%2e/dev"), "/dev");
        // Not a dot segment: only part of the segment is a dot
        assert_eq!(canon("/a/%2ehtaccess"), "/a/%2ehtaccess");
        assert_eq!(canon("/a/..."), "/a/...");
    }

    #[test]
    fn repeated_slashes_collapse() {
        assert_eq!(canon("//dev/"), "/dev/");
        assert_eq!(canon("/a//b///c"), "/a/b/c");
        assert_eq!(canon("/a//"), "/a/");
        assert_eq!(canon("//"), "/");
    }

    #[test]
    fn each_step_can_be_turned_off() {
        let no_merge = PathCanon {
            merge_slashes: false,
            ..ALL
        };
        assert_eq!(canonical_path("/a//b/./c", no_merge), "/a//b/c");
        assert_eq!(canonical_path("/a//..", no_merge), "/a/");
        let no_dots = PathCanon {
            resolve_dot_segments: false,
            ..ALL
        };
        assert_eq!(canonical_path("/a//./b", no_dots), "/a/./b");
        let none = PathCanon {
            resolve_dot_segments: false,
            merge_slashes: false,
            lowercase: false,
        };
        assert!(matches!(canonical_path("/A//./b", none), Cow::Borrowed(_)));
    }

    #[test]
    fn lowercasing_follows_normalize_paths() {
        let lower = PathCanon {
            lowercase: true,
            ..ALL
        };
        assert_eq!(canonical_path("/Threat_Bot/X", lower), "/threat_bot/x");
        assert_eq!(canonical_path("/A/./B//C", lower), "/a/b/c");
        assert_eq!(
            canonical_path("/Encryption/Fun/FractalTree/", ALL),
            "/Encryption/Fun/FractalTree/"
        );
    }
}
