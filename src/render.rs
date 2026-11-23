//! Turning findings into the final JSON record.
//!
//! Templates are rendered with JSON auto-escaping, so `{{ value }}` always
//! emits a valid JSON value: a string is quoted and escaped, a map becomes an
//! object, and `none` becomes `null`. Whatever the model wrote can therefore
//! never break the document; only the template can.

use anyhow::{Context, Result, bail};
use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

pub const DEFAULT_TEMPLATE: &str = include_str!("../templates/default.json.j2");

/// Render `template` with `context` and parse the result as JSON.
pub fn render(template: &str, name: &str, context: &impl Serialize) -> Result<Value> {
    let mut env = Environment::new();
    env.set_auto_escape_callback(|_| AutoEscape::Json);
    // Printing a misspelled variable is an error; testing one in `{% if %}`
    // is not, so optional values stay easy to handle.
    env.set_undefined_behavior(UndefinedBehavior::SemiStrict);
    env.add_template(name, template)
        .with_context(|| format!("could not parse template {name}"))?;
    let rendered = env
        .get_template(name)?
        .render(context)
        .map_err(|error| anyhow::anyhow!("{error:#}"))
        .with_context(|| format!("could not render template {name}"))?;
    serde_json::from_str(&rendered).map_err(|error| {
        let line = rendered
            .lines()
            .nth(error.line().saturating_sub(1))
            .unwrap_or_default();
        anyhow::anyhow!(
            "template {name} did not produce valid JSON: {error}\n  {}: {line}",
            error.line()
        )
    })
}

/// Validate `record` against a JSON schema, such as the CVE project's
/// `CVE_Record_Format_bundled.json`. Returns one message per violation.
pub fn validate(schema: &Path, record: &Value) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(schema)
        .with_context(|| format!("could not read {}", schema.display()))?;
    let schema: Value = serde_json::from_str(&raw)
        .with_context(|| format!("{} is not valid JSON", schema.display()))?;
    let validator = match jsonschema::validator_for(&schema) {
        Ok(validator) => validator,
        Err(error) => bail!("invalid schema: {error}"),
    };
    Ok(validator
        .iter_errors(record)
        .map(|error| format!("{}: {error}", error.instance_path))
        .collect())
}

/// Serialize with four-space indentation, like records from CVE Services.
pub fn to_pretty(value: &Value) -> Result<String> {
    let mut buffer = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
    value.serialize(&mut serializer)?;
    buffer.push(b'\n');
    Ok(String::from_utf8(buffer)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn values_are_json_encoded() {
        let context = json!({"text": "a \"quoted\"\nline", "missing": null, "list": [1, 2]});
        let value = render(
            r#"{"text": {{ text }}, "missing": {{ missing }}, "list": {{ list }}}"#,
            "t",
            &context,
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"text": "a \"quoted\"\nline", "missing": null, "list": [1, 2]})
        );
    }

    #[test]
    fn a_misspelled_variable_is_an_error() {
        let error = render(r#"{"a": {{ mispelled }}}"#, "t", &json!({}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("render"), "{error}");
    }

    #[test]
    fn invalid_json_points_at_the_line() {
        let error = render("{\n\"a\": 1,\n}", "t", &json!({}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("3: }"), "{error}");
    }

    #[test]
    fn the_severity_rationale_is_the_metric_description() {
        let metric = |severity: Value| {
            let context = json!({
                "cve_id": "CVE-2025-0001",
                "project": "demo",
                "generator": "draftcve",
                "repo_url": null,
                "issue_url": null,
                "commits": [],
                "issues": [],
                "advisories": [],
                "vars": {},
                "severity": severity,
            });
            let record = render(DEFAULT_TEMPLATE, "default.json.j2", &context).unwrap();
            record["containers"]["cna"]["metrics"][0]["other"]["content"].clone()
        };
        assert_eq!(
            metric(json!({"rating": "Low", "rationale": "Needs local access."})),
            json!({"value": "Low", "description": "Needs local access."})
        );
        assert_eq!(
            metric(json!({"rating": "Low", "rationale": null})),
            json!({"value": "Low"})
        );
    }

    #[test]
    fn credits_keep_their_type() {
        let context = json!({
            "cve_id": "CVE-2025-0001",
            "project": "demo",
            "generator": "draftcve",
            "repo_url": null,
            "issue_url": null,
            "commits": [],
            "issues": [],
            "advisories": [],
            "vars": {},
            "credits": [
                {"type": "finder", "value": "Jane Doe"},
                {"type": "remediation developer", "value": "John Doe"},
            ],
        });
        let record = render(DEFAULT_TEMPLATE, "default.json.j2", &context).unwrap();
        assert_eq!(
            record["containers"]["cna"]["credits"],
            json!([
                {"lang": "en", "type": "finder", "value": "Jane Doe"},
                {"lang": "en", "type": "remediation developer", "value": "John Doe"},
            ])
        );
    }

    #[test]
    fn issues_are_referenced_without_a_repository() {
        let references = |issue_url: Value, vars: Value| {
            let context = json!({
                "cve_id": "CVE-2025-0001",
                "project": "demo",
                "generator": "draftcve",
                "repo_url": null,
                "issue_url": issue_url,
                "commits": [],
                "issues": ["42"],
                "advisories": [],
                "vars": vars,
            });
            let record = render(DEFAULT_TEMPLATE, "default.json.j2", &context).unwrap();
            record["containers"]["cna"]["references"].clone()
        };
        assert_eq!(
            references(
                json!("https://bugs.example.org/show_bug.cgi?id="),
                json!({})
            ),
            json!([{
                "url": "https://bugs.example.org/show_bug.cgi?id=42",
                "tags": ["issue-tracking"]
            }])
        );
        assert_eq!(
            references(json!(null), json!({"issue_url": "https://example.org/i/"}))[0]["url"],
            json!("https://example.org/i/42")
        );
        assert_eq!(
            references(json!(null), json!({}))[0]["url"],
            json!("https://www.cve.org/CVERecord?id=CVE-2025-0001")
        );
    }

    #[test]
    fn maps_keep_their_order() {
        let value = render(r#"{{ {"b": 1, "a": 2} }}"#, "t", &json!({})).unwrap();
        assert_eq!(
            to_pretty(&value).unwrap(),
            "{\n    \"b\": 1,\n    \"a\": 2\n}\n"
        );
    }
}
