//! The README's lists that name code are held to the code: a command-line
//! option, an admin route or a source module the README leaves out, or names
//! when the code no longer has it, fails the build. Each of the three had
//! drifted (an option table without four options, an admin table without
//! eighteen routes, a module tree without forty modules).

use std::collections::BTreeSet;
use std::path::Path;

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|e| panic!("{relative}: {e}"))
        .replace("\r\n", "\n")
}

/// The fenced block that follows `heading` in `text`.
fn block_after(text: &str, heading: &str) -> String {
    let at = text
        .find(heading)
        .unwrap_or_else(|| panic!("README has no {heading:?}"));
    let rest = &text[at..];
    let fenced = &rest[rest.find("```").expect("a fenced block after the heading")..];
    let body = &fenced[fenced.find('\n').expect("the fence's line") + 1..];
    body[..body.find("```").expect("the end of the fenced block")].to_string()
}

/// The text of `heading`'s section: up to the next heading of its level.
fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let at = text
        .find(heading)
        .unwrap_or_else(|| panic!("README has no {heading:?}"));
    let rest = &text[at + heading.len()..];
    let level = heading.split(' ').next().unwrap_or("##");
    let next = rest.find(&format!("\n{level} ")).unwrap_or(rest.len());
    &rest[..next]
}

/// The README's "CLI Arguments" block is the proxy's own `--help`.
#[test]
fn the_cli_block_is_the_help() {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_pqcrypta-proxy"));
    command.arg("--help");
    // The help shows an option's environment variable with its value when set
    for (name, _) in std::env::vars() {
        if name.starts_with("PQCRYPTA_") {
            command.env_remove(name);
        }
    }
    let output = command.output().expect("running pqcrypta-proxy --help");
    assert!(output.status.success());
    let normalise = |text: &str| {
        text.replace("pqcrypta-proxy.exe", "pqcrypta-proxy")
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string()
    };
    let help = normalise(&String::from_utf8_lossy(&output.stdout));
    let block = normalise(&block_after(&read("README.md"), "## CLI Arguments"));
    assert_eq!(
        block, help,
        "the README's CLI block is not `pqcrypta-proxy --help`, which reads:\n{help}"
    );
}

/// Every route the admin router registers is in the README's admin tables,
/// with its method, and every route those tables name is registered.
#[test]
fn the_admin_tables_list_every_route() {
    let source = read("src/admin.rs");
    // The router, not the tests' own
    let source = source.split("\n#[cfg(test)]").next().unwrap_or(&source);
    let mut registered = BTreeSet::new();
    let mut rest = source;
    // `.route("/path", get(handler))`, the path on the same line or the next
    while let Some(at) = rest.find(".route(") {
        let after = rest[at + ".route(".len()..].trim_start();
        rest = after;
        let Some(after) = after.strip_prefix('"') else {
            continue;
        };
        let path_end = after.find('"').expect("the route's closing quote");
        let path = &after[..path_end];
        let until = after.find(".route(").unwrap_or(after.len()).min(400);
        let call = &after[path_end..until];
        for method in ["get", "post", "put", "delete", "patch"] {
            let token = format!("{method}(");
            let mut from = 0;
            while let Some(found) = call[from..].find(&token) {
                let start = from + found;
                let preceded = call[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
                if !preceded {
                    registered.insert((method.to_ascii_uppercase(), path.to_string()));
                }
                from = start + token.len();
            }
        }
    }
    assert!(registered.len() > 20, "the route scan found {registered:?}");

    let readme = read("README.md");
    let documented: BTreeSet<(String, String)> = section(&readme, "## Admin API\n")
        .lines()
        .filter_map(|line| {
            let mut cells = line.strip_prefix("| `")?.split('|');
            let path = cells.next()?.trim().trim_end_matches('`').to_string();
            let method = cells.next()?.trim().to_string();
            Some((method, path))
        })
        .collect();

    let missing: Vec<_> = registered.difference(&documented).collect();
    let gone: Vec<_> = documented.difference(&registered).collect();
    assert!(
        missing.is_empty() && gone.is_empty(),
        "admin routes the README does not list: {missing:?}; listed but not registered: {gone:?}"
    );
}

/// The README's module tree names every file and directory in src/, and
/// nothing src/ does not have.
#[test]
fn the_module_tree_names_every_module() {
    let readme = read("README.md");
    let tree = block_after(&readme, "## Module Structure");
    let named: BTreeSet<String> = tree
        .lines()
        .filter_map(|line| line.split_once("── ").map(|(_, rest)| rest))
        .filter_map(|rest| rest.split_whitespace().next().map(str::to_string))
        .collect();
    let mut present = BTreeSet::new();
    for entry in std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().unwrap().is_dir() {
            present.insert(format!("{name}/"));
        } else if Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
        {
            present.insert(name);
        }
    }
    let missing: Vec<_> = present.difference(&named).collect();
    let gone: Vec<_> = named.difference(&present).collect();
    assert!(
        missing.is_empty() && gone.is_empty(),
        "modules the README's tree leaves out: {missing:?}; in the tree but not in src/: {gone:?}"
    );
}

/// One entry of each list and map the configuration holds, with only the
/// fields that have no default: what a file that names nothing else gets.
const ENTRIES: &str = r#"
[backends.doh]
name = "doh"
type = "http1"
address = "127.0.0.1:1"

[backend_pools.pool]
name = "pool"
[[backend_pools.pool.servers]]
address = "127.0.0.1:1"

[[routes]]
[routes.security]
[routes.cors]

[[passthrough_routes]]
sni = "passthrough.example"
backend = "127.0.0.1:1"

[advanced_rate_limiting.route_limits.route]
pattern = "/"

[[advanced_rate_limiting.composite_keys]]
name = "composite"
keys = ["source_ip"]
[advanced_rate_limiting.composite_keys.limits]
"#;

/// The table a TOML header line names: `[a.b]` or `[[a.b]]`.
fn toml_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(inner);
    inner
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        .then(|| inner.to_string())
}

/// The serialised table a documented section names. A list's entry is its
/// first; a name in capitals (`POOL_NAME`) stands for any entry of a map.
fn resolve<'a>(config: &'a serde_json::Value, section: &str) -> Option<&'a serde_json::Value> {
    let mut node = config;
    for part in section.split('.') {
        if let Some(first) = node.as_array().and_then(|a| a.first()) {
            node = first;
        }
        let map = node.as_object()?;
        node = if part.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            map.values().next()?
        } else {
            map.get(part)?
        };
    }
    if let Some(first) = node.as_array().and_then(|a| a.first()) {
        node = first;
    }
    node.is_object().then_some(node)
}

/// A documented default as a value: a TOML literal, or `null` for none.
fn stated_value(text: &str) -> Option<serde_json::Value> {
    let literal = text.strip_prefix('`')?.strip_suffix('`')?;
    if literal == "null" {
        return Some(serde_json::Value::Null);
    }
    let table: toml::Table = toml::from_str(&format!("v = {literal}")).ok()?;
    serde_json::to_value(table.get("v")?).ok()
}

/// Equal as configuration values: numbers by value, so `3` documents `3.0`.
fn same(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    match (a, b) {
        (serde_json::Value::Number(x), serde_json::Value::Number(y)) => x.as_f64() == y.as_f64(),
        (serde_json::Value::Array(x), serde_json::Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        _ => a == b,
    }
}

/// Every default docs/CONFIG.md states is the code's. A row of a table with
/// a Default column belongs to the TOML table its section's example names;
/// its key must be a setting of that table, and its default the value the
/// code gives a file that leaves the key out, for the top-level tables and
/// for an entry of each list and map alike.
#[test]
fn the_config_reference_states_the_code_defaults() {
    let (config, _) =
        pqcrypta_proxy::config::parse_config_str(ENTRIES).expect("one entry of each kind parses");
    let code = serde_json::to_value(&config).expect("the configuration serialises");
    let doc = read("docs/CONFIG.md");
    // The table a `##` section's example names, which its `###` subsections
    // share unless their own example names another.
    let mut section_table: Option<String> = None;
    let mut in_subsection = false;
    let mut table: Option<String> = None;
    let mut fence: Option<bool> = None; // inside a fenced block; true for TOML
    let mut default_column = false;
    let mut checked = 0;
    let mut wrong = Vec::new();
    for line in doc.lines() {
        let line = line.trim();
        if let Some(info) = line.strip_prefix("```") {
            fence = if fence.is_some() {
                None
            } else {
                Some(info == "toml")
            };
            continue;
        }
        match fence {
            Some(true) => {
                if let Some(name) = toml_header(line) {
                    if !in_subsection {
                        section_table = Some(name.clone());
                    }
                    table = Some(name);
                }
                continue;
            }
            Some(false) => continue,
            None => {}
        }
        if line.starts_with("## ") {
            section_table = None;
            in_subsection = false;
            table = None;
            default_column = false;
            continue;
        }
        if line.starts_with("### ") {
            in_subsection = true;
            table.clone_from(&section_table);
            default_column = false;
            continue;
        }
        let Some(row) = line.strip_prefix('|').and_then(|r| r.strip_suffix('|')) else {
            continue;
        };
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        if cells.first() == Some(&"Option") {
            default_column = cells.get(2) == Some(&"Default");
            continue;
        }
        let Some(key) = cells
            .first()
            .and_then(|c| c.strip_prefix('`'))
            .and_then(|c| c.strip_suffix('`'))
        else {
            continue;
        };
        if !default_column {
            continue;
        }
        let Some(section) = &table else {
            wrong.push(format!("`{key}`: no TOML example above it names its table"));
            continue;
        };
        let Some(actual) = resolve(&code, section).and_then(|t| t.get(key)) else {
            wrong.push(format!("[{section}] {key}: not a setting of that table"));
            continue;
        };
        checked += 1;
        let stated = cells.get(2).copied().unwrap_or_default();
        if stated == "required" {
            continue;
        }
        match stated_value(stated) {
            Some(value) if same(&value, actual) => {}
            Some(_) => wrong.push(format!(
                "[{section}] {key}: documented {stated}, the code's default is {actual}"
            )),
            None => wrong.push(format!(
                "[{section}] {key}: the default {stated} is not a TOML value or `null`"
            )),
        }
    }
    assert!(
        checked > 150,
        "only {checked} documented defaults were found to check"
    );
    assert!(wrong.is_empty(), "docs/CONFIG.md:\n{}", wrong.join("\n"));
}

/// The non-test code of every `.rs` file under `dir`.
fn source_under(dir: &Path, out: &mut String) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            out.push_str(&without_test_module(&text));
            out.push('\n');
        }
    }
}

/// A source file without its test modules. Each is cut from its
/// `#[cfg(test)]` to the `}` that closes it at the start of a line (rustfmt
/// indents everything inside a top-level module): tls.rs and security.rs keep
/// test modules between their items, so cutting at the first would hide the
/// code after it.
fn without_test_module(text: &str) -> String {
    let module =
        regex::Regex::new(r"(?ms)^#\[cfg\(test\)\]\n(?:#\[[^\n]*\]\n)*mod \w+ \{\n.*?^\}\n")
            .unwrap();
    module.replace_all(text, "").into_owned()
}

/// Every setting the configuration file accepts is read by the code: each
/// field of a deserialised struct in src/config.rs appears somewhere as
/// `.field`. A setting nothing reads is a feature the documents describe and
/// the proxy does not have; `routes.stream_to_method` was one, documented in
/// docs/CONFIG.md and read by nothing until it was built.
#[test]
fn every_setting_is_read() {
    let mut code = String::new();
    source_under(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut code,
    );
    let config = read("src/config.rs");
    let config = without_test_module(&config);
    let config = config.as_str();
    let structs = regex::Regex::new(
        r"(?s)#\[derive\(([^\]]*)\)\]\s*(?:#\[[^\]]*\]\s*)*pub struct (\w+)\s*\{(.*?)\n\}",
    )
    .unwrap();
    let field = regex::Regex::new(r"(?m)^\s+pub (\w+)\s*:").unwrap();
    let mut unread = Vec::new();
    let mut settings = 0;
    for s in structs.captures_iter(config) {
        if !s[1].contains("Deserialize") {
            continue;
        }
        for f in field.captures_iter(&s[3]) {
            settings += 1;
            let name = &f[1];
            let used = code.match_indices(&format!(".{name}")).any(|(at, _)| {
                !code[at + 1 + name.len()..]
                    .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            });
            if !used {
                unread.push(format!("{}.{name}", &s[2]));
            }
        }
    }
    assert!(settings > 400, "only {settings} settings found");
    assert!(unread.is_empty(), "settings no code reads: {unread:?}");
}
