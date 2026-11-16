//! The CWE catalog, as published by MITRE.
//!
//! Small models recall CWE numbers poorly: the concept is usually right but
//! the number is not, or the entry is one MITRE prohibits for mapping. So the
//! model looks entries up here, and `write_cwe` is checked against the
//! catalog's own mapping guidance (`Mapping_Notes/Usage`).
//!
//! The catalog is read from the official XML (`cwec_v*.xml`), downloadable
//! from <https://cwe.mitre.org/data/downloads.html>.

use anyhow::{Context, Result, bail};
use quick_xml::XmlVersion;
use quick_xml::events::Event;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The view whose `ChildOf` relations form the research hierarchy.
const RESEARCH_VIEW: &str = "1000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Weakness,
    /// A category, called a grouping since CWE 5.0.
    Grouping,
    View,
}

/// Whether MITRE allows mapping a vulnerability to an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    Allowed,
    AllowedWithReview,
    Discouraged,
    Prohibited,
}

impl Usage {
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "Allowed" => Some(Self::Allowed),
            "Allowed-with-Review" => Some(Self::AllowedWithReview),
            "Discouraged" => Some(Self::Discouraged),
            "Prohibited" => Some(Self::Prohibited),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::AllowedWithReview => "Allowed-with-Review",
            Self::Discouraged => "Discouraged",
            Self::Prohibited => "Prohibited",
        }
    }

    pub fn mappable(self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedWithReview)
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u32,
    pub name: String,
    pub kind: Kind,
    /// Pillar, Class, Base, or Variant; weaknesses only.
    pub abstraction: Option<String>,
    pub status: String,
    pub description: String,
    pub usage: Usage,
    pub rationale: String,
    /// Entries MITRE suggests instead, with its comment.
    pub suggestions: Vec<(u32, String)>,
    /// `ChildOf` in the research view.
    pub parents: Vec<u32>,
}

pub struct Catalog {
    pub version: String,
    entries: BTreeMap<u32, Entry>,
    children: BTreeMap<u32, Vec<u32>>,
    /// Stemmed terms of each mappable weakness's name and description.
    index: Vec<(u32, BTreeSet<String>, BTreeSet<String>)>,
    /// How many indexed entries each term appears in.
    frequency: BTreeMap<String, usize>,
}

/// The outcome of checking a proposed mapping.
pub enum Verdict<'a> {
    /// Fine as is.
    Accepted(&'a Entry),
    /// Allowed, but a more specific child may fit better.
    Review(&'a Entry),
    /// MITRE discourages it; another entry should normally be chosen.
    Discouraged(&'a Entry),
}

/// Pick the newest `cwec_v*.xml` when given a directory.
pub fn locate(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    if !path.is_dir() {
        return Ok(path.to_path_buf());
    }
    let mut candidates = vec![];
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(version) = name
            .strip_prefix("cwec_v")
            .and_then(|rest| rest.strip_suffix(".xml"))
        {
            candidates.push((version.to_string(), name));
        }
    }
    candidates.sort_by(|a, b| crate::release::compare_versions(&a.0, &b.0));
    match candidates.pop() {
        Some((_, name)) => Ok(path.join(name)),
        None => bail!("no cwec_v*.xml in {}", path.display()),
    }
}

/// Which text field of an entry is being read.
#[derive(Clone, Copy, PartialEq)]
enum Field {
    Description,
    Usage,
    Rationale,
}

impl Catalog {
    pub fn load(path: &Path) -> Result<Self> {
        let path = locate(path)?;
        let mut reader = quick_xml::Reader::from_file(&path)
            .with_context(|| format!("could not open {}", path.display()))?;
        Self::parse(&mut reader).with_context(|| format!("could not parse {}", path.display()))
    }

    fn parse<R: std::io::BufRead>(reader: &mut quick_xml::Reader<R>) -> Result<Self> {
        let mut version = String::new();
        let mut entries = BTreeMap::new();
        let mut stack: Vec<String> = vec![];
        let mut current: Option<(Entry, Option<String>)> = None;
        let mut field: Option<(Field, usize)> = None;
        let mut text = String::new();
        let mut buf = vec![];

        loop {
            let event = reader.read_event_into(&mut buf)?;
            match &event {
                Event::Start(start) | Event::Empty(start) => {
                    let name = start.local_name().as_ref().to_string();
                    let mut attributes = BTreeMap::new();
                    for attribute in start.attributes() {
                        let attribute = attribute?;
                        let key = attribute.key.local_name().as_ref().to_string();
                        let value = attribute.normalized_value(XmlVersion::Implicit1_0)?;
                        attributes.insert(key, value.into_owned());
                    }
                    let get = |key: &str| attributes.get(key).cloned().unwrap_or_default();
                    let parent = stack.last().map(String::as_str);
                    let kind = match (parent, name.as_str()) {
                        (Some("Weaknesses"), "Weakness") => Some(Kind::Weakness),
                        (Some("Groupings" | "Categories"), "Grouping" | "Category") => {
                            Some(Kind::Grouping)
                        }
                        (Some("Views"), "View") => Some(Kind::View),
                        _ => None,
                    };
                    if name == "Weakness_Catalog" {
                        version = get("Version");
                    }
                    if let Some(kind) = kind {
                        let id = get("ID").parse().context("entry without a numeric ID")?;
                        let entry = Entry {
                            id,
                            name: get("Name"),
                            kind,
                            abstraction: attributes.get("Abstraction").cloned(),
                            status: get("Status"),
                            description: String::new(),
                            // Entries predating mapping notes are treated
                            // as weaknesses always were: allowed.
                            usage: if kind == Kind::Weakness {
                                Usage::Allowed
                            } else {
                                Usage::Prohibited
                            },
                            rationale: String::new(),
                            suggestions: vec![],
                            parents: vec![],
                        };
                        current = Some((entry, None));
                    } else if let Some((entry, _)) = current.as_mut() {
                        let path: Vec<_> = stack.iter().rev().take(2).map(String::as_str).collect();
                        match (name.as_str(), path.as_slice()) {
                            ("Description" | "Summary" | "Objective", [_entry, _])
                                if stack.len() == 3 =>
                            {
                                field = Some((Field::Description, stack.len()));
                            }
                            ("Usage", ["Mapping_Notes", ..]) => {
                                field = Some((Field::Usage, stack.len()));
                            }
                            ("Rationale", ["Mapping_Notes", ..]) => {
                                field = Some((Field::Rationale, stack.len()));
                            }
                            ("Suggestion", ["Suggestions", "Mapping_Notes"]) => {
                                if let Ok(id) = get("CWE_ID").parse() {
                                    entry.suggestions.push((id, get("Comment")));
                                }
                            }
                            ("Related_Weakness", ["Related_Weaknesses", ..])
                                if get("Nature") == "ChildOf"
                                    && get("View_ID") == RESEARCH_VIEW =>
                            {
                                if let Ok(id) = get("CWE_ID").parse() {
                                    entry.parents.push(id);
                                }
                            }
                            _ => {}
                        }
                    }
                    if matches!(event, Event::Start(_)) {
                        stack.push(name);
                    }
                }
                Event::Text(content) if field.is_some() => text.push_str(&content.xml10_content()),
                Event::CData(content) if field.is_some() => text.push_str(&content.xml10_content()),
                Event::GeneralRef(reference) if field.is_some() => {
                    if let Some(c) = reference.resolve_char_ref()? {
                        text.push(c);
                    } else if let Some(resolved) =
                        quick_xml::escape::resolve_predefined_entity(&reference.xml10_content())
                    {
                        text.push_str(resolved);
                    }
                }
                Event::End(_) => {
                    let depth = stack.len();
                    stack.pop();
                    if let Some((which, at)) = field
                        && at == depth - 1
                    {
                        let value = text.split_whitespace().collect::<Vec<_>>().join(" ");
                        if let Some((entry, usage)) = current.as_mut() {
                            match which {
                                Field::Description => entry.description = value,
                                Field::Usage => *usage = Some(value),
                                Field::Rationale => entry.rationale = value,
                            }
                        }
                        field = None;
                        text.clear();
                    }
                    if depth == 3
                        && let Some((mut entry, usage)) = current.take()
                    {
                        if let Some(usage) = usage.as_deref().and_then(Usage::parse) {
                            entry.usage = usage;
                        }
                        if entry.status == "Deprecated" || entry.status == "Obsolete" {
                            entry.usage = Usage::Prohibited;
                        }
                        entries.insert(entry.id, entry);
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        if entries.is_empty() {
            bail!("no CWE entries found; is this a CWE catalog (cwec_v*.xml)?");
        }
        let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for entry in entries.values() {
            for parent in &entry.parents {
                children.entry(*parent).or_default().push(entry.id);
            }
        }
        let index: Vec<_> = entries
            .values()
            .filter(|entry| entry.kind == Kind::Weakness && entry.usage.mappable())
            .map(|entry| (entry.id, terms(&entry.name), terms(&entry.description)))
            .collect();
        let mut frequency: BTreeMap<String, usize> = BTreeMap::new();
        for (_, name, description) in &index {
            for term in name.union(description) {
                *frequency.entry(term.clone()).or_default() += 1;
            }
        }
        Ok(Self {
            version,
            entries,
            children,
            index,
            frequency,
        })
    }

    pub fn get(&self, id: u32) -> Option<&Entry> {
        self.entries.get(&id)
    }

    /// One line per entry, for listings shown to the model.
    pub fn summary(&self, entry: &Entry) -> String {
        let mut text = format!("CWE-{} {}", entry.id, entry.name);
        let mut notes = vec![];
        if let Some(abstraction) = &entry.abstraction {
            notes.push(abstraction.clone());
        }
        notes.push(entry.usage.name().to_string());
        text.push_str(&format!(" ({})", notes.join(", ")));
        text
    }

    /// Mappable children, most specific candidates for a too-general entry.
    pub fn mappable_children(&self, id: u32) -> Vec<&Entry> {
        self.children
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|child| self.get(*child))
            .filter(|child| child.usage.mappable())
            .collect()
    }

    /// Everything the model needs to judge whether an entry fits.
    pub fn describe(&self, entry: &Entry) -> String {
        let mut text = format!("{}\n\n{}\n", self.summary(entry), entry.description);
        if !entry.rationale.is_empty() {
            text.push_str(&format!(
                "\nMapping: {}. {}\n",
                entry.usage.name(),
                entry.rationale
            ));
        }
        let parents: Vec<_> = entry
            .parents
            .iter()
            .filter_map(|id| self.get(*id))
            .map(|parent| format!("- {}", self.summary(parent)))
            .collect();
        if !parents.is_empty() {
            text.push_str(&format!("\nParents:\n{}\n", parents.join("\n")));
        }
        let children: Vec<_> = self
            .mappable_children(entry.id)
            .into_iter()
            .take(20)
            .map(|child| format!("- {}", self.summary(child)))
            .collect();
        if !children.is_empty() {
            text.push_str(&format!(
                "\nMore specific entries:\n{}\n",
                children.join("\n")
            ));
        }
        let suggestions = self.suggestions(entry);
        if !suggestions.is_empty() {
            text.push_str(&format!("\nSuggested instead:\n{suggestions}\n"));
        }
        text
    }

    fn suggestions(&self, entry: &Entry) -> String {
        entry
            .suggestions
            .iter()
            .filter_map(|(id, comment)| self.get(*id).map(|e| (e, comment)))
            .map(|(suggested, comment)| {
                if comment.is_empty() || comment.eq_ignore_ascii_case(&suggested.name) {
                    format!("- {}", self.summary(suggested))
                } else {
                    format!("- {}: {comment}", self.summary(suggested))
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Mappable weaknesses matching `query`, best first.
    ///
    /// Terms are weighted by rarity, so `NUL` and `truncated` decide the
    /// ranking rather than `character` or `user`.
    pub fn search(&self, query: &str, limit: usize) -> Vec<&Entry> {
        let query = terms(query);
        let total = self.index.len().max(1) as f64;
        let mut scored: Vec<_> = self
            .index
            .iter()
            .filter_map(|(id, name, description)| {
                let mut score = 0.0;
                for term in &query {
                    let weight = match self.frequency.get(term) {
                        Some(count) => (total / *count as f64).ln(),
                        None => continue,
                    };
                    if name.contains(term) {
                        score += 3.0 * weight;
                    } else if description.contains(term) {
                        score += weight;
                    }
                }
                if score == 0.0 {
                    return None;
                }
                let entry = self.get(*id)?;
                // Base and Variant are MITRE's preferred mapping levels.
                if matches!(entry.abstraction.as_deref(), Some("Base" | "Variant")) {
                    score *= 1.1;
                }
                Some((score, entry))
            })
            .collect();
        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.id.cmp(&b.1.id)));
        scored
            .into_iter()
            .take(limit)
            .map(|(_, entry)| entry)
            .collect()
    }

    /// The entry whose name `name` is, if any.
    pub fn find_by_name(&self, name: &str) -> Option<&Entry> {
        self.entries
            .values()
            .filter(|entry| entry.usage != Usage::Prohibited || entry.kind == Kind::Weakness)
            .find(|entry| names_match(name, &entry.name))
    }

    /// Check a mapping the model proposed: `id` must exist, be mappable, and
    /// be the entry `name` describes.
    pub fn check(&self, id: u32, name: Option<&str>) -> Result<Verdict<'_>> {
        let Some(entry) = self.get(id) else {
            let mut message = format!("CWE-{id} does not exist in CWE {}.", self.version);
            if let Some(found) = name.and_then(|name| self.find_by_name(name)) {
                message.push_str(&format!(" Did you mean {}?", self.summary(found)));
            }
            message.push_str(" Use `search_cwe` to find the right entry.");
            bail!(message);
        };
        if let Some(name) = name
            && !names_match(name, &entry.name)
        {
            let mut message = format!("CWE-{id} is \"{}\", not \"{name}\".", entry.name);
            if let Some(found) = self.find_by_name(name) {
                message.push_str(&format!(" Did you mean {}?", self.summary(found)));
            }
            message.push_str(" Use `search_cwe` or `read_cwe` to check the number.");
            bail!(message);
        }
        match entry.usage {
            Usage::Prohibited => {
                let mut message = format!(
                    "{} must not be used for mapping vulnerabilities. {}",
                    self.summary(entry),
                    entry.rationale
                );
                let suggestions = self.suggestions(entry);
                if !suggestions.is_empty() {
                    message.push_str(&format!("\nConsider instead:\n{suggestions}"));
                }
                bail!(message);
            }
            Usage::Discouraged => Ok(Verdict::Discouraged(entry)),
            Usage::AllowedWithReview => Ok(Verdict::Review(entry)),
            Usage::Allowed => Ok(Verdict::Accepted(entry)),
        }
    }

    /// The text explaining why a discouraged entry was rejected.
    pub fn discouraged_message(&self, entry: &Entry) -> String {
        let mut message = format!(
            "{} is discouraged for mapping vulnerabilities. {}",
            self.summary(entry),
            entry.rationale
        );
        let mut alternatives = self.suggestions(entry);
        if alternatives.is_empty() {
            alternatives = self
                .mappable_children(entry.id)
                .into_iter()
                .take(10)
                .map(|child| format!("- {}", self.summary(child)))
                .collect::<Vec<_>>()
                .join("\n");
        }
        if !alternatives.is_empty() {
            message.push_str(&format!("\nConsider instead:\n{alternatives}"));
        }
        message.push_str(&format!(
            "\nIf none of them fits, call `write_cwe` with CWE-{} again.",
            entry.id
        ));
        message
    }
}

const STOPWORDS: &[&str] = &[
    "a",
    "an",
    "and",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "to",
    "via",
    "with",
    "when",
    "which",
    "that",
    "this",
    "can",
    "may",
    "not",
    "product",
    "attacker",
    "vulnerability",
    "issue",
    "flaw",
    "cwe",
];

fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty() && !STOPWORDS.contains(word))
        .map(str::to_string)
        .collect()
}

/// A crude stem, so `terminated` meets `termination` and `bytes` meets `byte`.
fn stem(word: String) -> String {
    // C's name for the null character.
    if word == "nul" {
        return "null".to_string();
    }
    if word.len() > 6 {
        word.chars().take(6).collect()
    } else {
        word.trim_end_matches('s').to_string()
    }
}

fn terms(text: &str) -> BTreeSet<String> {
    words(text).into_iter().map(stem).collect()
}

/// Whether two CWE names refer to the same entry, tolerating the paraphrase
/// and abbreviation models produce ("NUL termination" for "Improper Null
/// Termination").
pub fn names_match(a: &str, b: &str) -> bool {
    let (a, b) = (terms(a), terms(b));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a.is_subset(&b) || b.is_subset(&a) {
        return true;
    }
    let common = a.intersection(&b).count();
    let all = a.union(&b).count();
    common * 2 >= all
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="5.0" xmlns="http://cwe.mitre.org/cwe-8">
  <Weaknesses>
    <Weakness ID="20" Name="Improper Input Validation" Abstraction="Class" Status="Stable">
      <Description>The product receives input but does not validate it.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="707" View_ID="1000"/>
      </Related_Weaknesses>
      <Mapping_Notes>
        <Usage>Discouraged</Usage>
        <Rationale>CWE-20 is commonly misused.</Rationale>
        <Suggestions>
          <Suggestion CWE_ID="1284" Comment="Specified Quantity"/>
        </Suggestions>
      </Mapping_Notes>
    </Weakness>
    <Weakness ID="170" Name="Improper Null Termination" Abstraction="Base" Status="Incomplete">
      <Description>The product does not terminate or incorrectly terminates a string or array with a null character or equivalent terminator.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="707" View_ID="1000"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="700"/>
      </Related_Weaknesses>
      <Observed_Examples>
        <Observed_Example><Description>Not the entry's description.</Description></Observed_Example>
      </Observed_Examples>
      <Mapping_Notes><Usage>Allowed</Usage><Rationale>Base level.</Rationale></Mapping_Notes>
    </Weakness>
    <Weakness ID="707" Name="Improper Neutralization" Abstraction="Pillar" Status="Incomplete">
      <Description>The product does not ensure that structured messages are well-formed.</Description>
      <Mapping_Notes><Usage>Discouraged</Usage><Rationale>Pillar.</Rationale></Mapping_Notes>
    </Weakness>
    <Weakness ID="1284" Name="Improper Validation of Specified Quantity in Input" Abstraction="Base" Status="Incomplete">
      <Description>The product receives input that is expected to specify a quantity &amp; does not validate it.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="1187" Name="DEPRECATED: Use of Uninitialized Resource" Abstraction="Base" Status="Deprecated">
      <Description>This entry has been deprecated because it was a duplicate of CWE-908.</Description>
    </Weakness>
  </Weaknesses>
  <Groupings>
    <Grouping ID="1035" Name="OWASP Top Ten 2017 Category A9" Status="Incomplete">
      <Summary>Weaknesses in this category are related to A9.</Summary>
      <Mapping_Notes><Usage>Prohibited</Usage><Rationale>This entry is a Category.</Rationale></Mapping_Notes>
    </Grouping>
  </Groupings>
</Weakness_Catalog>
"#;

    /// A small catalog for tests elsewhere.
    pub fn catalog() -> Catalog {
        Catalog::parse(&mut quick_xml::Reader::from_str(SAMPLE)).unwrap()
    }

    #[test]
    fn entries_are_parsed() {
        let catalog = catalog();
        assert_eq!(catalog.version, "5.0");
        let entry = catalog.get(170).unwrap();
        assert_eq!(entry.name, "Improper Null Termination");
        assert!(
            entry
                .description
                .starts_with("The product does not terminate")
        );
        assert_eq!(entry.usage, Usage::Allowed);
        assert_eq!(entry.parents, vec![707], "only the research view counts");
        assert_eq!(catalog.get(20).unwrap().suggestions.len(), 1);
        assert!(
            catalog
                .get(1284)
                .unwrap()
                .description
                .contains("quantity & does")
        );
        assert_eq!(catalog.get(1187).unwrap().usage, Usage::Prohibited);
        assert_eq!(catalog.get(1035).unwrap().kind, Kind::Grouping);
        assert_eq!(catalog.mappable_children(20)[0].id, 1284);
    }

    #[test]
    fn a_right_entry_is_accepted() {
        let catalog = catalog();
        assert!(matches!(
            catalog.check(170, Some("NULL termination")),
            Ok(Verdict::Accepted(_))
        ));
        assert!(matches!(catalog.check(170, None), Ok(Verdict::Accepted(_))));
    }

    #[test]
    fn a_wrong_number_points_at_the_named_entry() {
        let error = catalog()
            .check(20, Some("Improper Null Termination"))
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("CWE-20 is \"Improper Input Validation\""),
            "{error}"
        );
        assert!(error.contains("Did you mean CWE-170"), "{error}");
    }

    #[test]
    fn an_unknown_number_is_rejected() {
        let error = catalog()
            .check(99999, Some("Improper Null Termination"))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("does not exist in CWE 5.0"), "{error}");
        assert!(error.contains("Did you mean CWE-170"), "{error}");
    }

    #[test]
    fn prohibited_entries_are_rejected() {
        let catalog = catalog();
        let error = catalog.check(1035, None).err().unwrap().to_string();
        assert!(error.contains("must not be used"), "{error}");
        assert!(catalog.check(1187, None).is_err());
    }

    #[test]
    fn discouraged_entries_offer_suggestions() {
        let catalog = catalog();
        let Ok(Verdict::Discouraged(entry)) = catalog.check(20, None) else {
            panic!("CWE-20 should be discouraged");
        };
        let message = catalog.discouraged_message(entry);
        assert!(message.contains("CWE-1284"), "{message}");
    }

    #[test]
    fn search_finds_mappable_weaknesses() {
        let catalog = catalog();
        let found: Vec<_> = catalog
            .search("string not null terminated", 5)
            .iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(found.first(), Some(&170), "{found:?}");
        assert!(!found.contains(&707), "a discouraged pillar is not offered");
        assert!(catalog.search("the of", 5).is_empty());
    }

    #[test]
    fn names_tolerate_paraphrase() {
        assert!(names_match("Out of bounds write", "Out-of-bounds Write"));
        assert!(names_match(
            "Heap buffer overflow",
            "Heap-based Buffer Overflow"
        ));
        assert!(!names_match(
            "Out-of-bounds Write",
            "Improper Null Termination"
        ));
    }

    /// Against the real catalog, when `CWE_CATALOG` points at one.
    #[test]
    fn the_published_catalog_is_understood() {
        let Some(path) = std::env::var_os("CWE_CATALOG") else {
            return;
        };
        let started = std::time::Instant::now();
        let catalog = Catalog::load(Path::new(&path)).unwrap();
        eprintln!("loaded CWE {} in {:?}", catalog.version, started.elapsed());

        assert_eq!(catalog.get(170).unwrap().usage, Usage::Allowed);
        assert_eq!(catalog.get(787).unwrap().usage, Usage::AllowedWithReview);
        let buffer = catalog.get(119).unwrap();
        assert_eq!(buffer.usage, Usage::Discouraged);
        assert!(buffer.suggestions.iter().any(|(id, _)| *id == 787));
        assert_eq!(catalog.get(1187).unwrap().usage, Usage::Prohibited);
        assert_eq!(catalog.get(1035).map(|e| e.usage), Some(Usage::Prohibited));

        for (query, expected) in [
            ("string not null terminated", 170),
            ("username containing NUL character truncated", 626),
            ("out-of-bounds write heap", 787),
            ("integer overflow", 190),
            ("use after free", 416),
            ("certificate validation", 295),
        ] {
            let found: Vec<_> = catalog.search(query, 10).iter().map(|e| e.id).collect();
            eprintln!("{query}: {found:?}");
            assert!(found.contains(&expected), "{query}: {found:?}");
        }
    }
}
