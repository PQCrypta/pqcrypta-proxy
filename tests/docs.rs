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
