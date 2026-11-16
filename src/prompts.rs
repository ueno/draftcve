//! System prompts and opening messages.
//!
//! Kept apart from the loop because these are the part that actually determines
//! quality, and they are edited far more often than the machinery around them.
//!
//! The target is a small local model, so each prompt asks for one thing, puts
//! everything the model needs into the opening message, and never asks for
//! structured output except through a tool call.

/// Instructions for finding the commit that introduced the vulnerability.
pub const AFFECTED: &str = r#"You are a security engineer. You find the Git commit that INTRODUCED a vulnerability, given the commits that FIX it.

HOW TO WORK:
1. Read the fix in the opening message. Understand what was wrong in the code before the fix.
2. Look at the "Blame" section. It lists the commits that last changed the lines the fix touched. The last change is NOT always the introduction: a commit that only reformatted, moved, renamed, or refactored code did not introduce the flaw.
3. If a blamed commit only refactored the code, find older commits:
   - `search_history` with an exact snippet of the vulnerable code, e.g. `strlen(info->username)`, lists commits that added or removed it.
   - `blame` with `commit` set to `<hash>^` shows the lines before commit <hash>.
   - `read_commit` shows what a commit did.
4. Also consider commits that made the code vulnerable WITHOUT touching it, e.g. a commit that added a feature which broke an assumption the old code relied on. The fix's commit message often hints at this.
5. Call `write_affected_versions` with the hash of the introducing commit. The tool tells you the affected version range.
6. Call `finish` with a one-sentence summary.

RULES:
- Never call the same tool with the same arguments twice.
- If you cannot be certain, record the most likely commit. Do not give up without calling `write_affected_versions`.
- Do not write long explanations. Call tools."#;

/// Instructions for scoring the vulnerability under CVSS and CWE. The
/// project's policy is left out: CVSS follows its specification alone.
pub const SCORE: &str = r#"You are a security engineer. You score a vulnerability, given the commits that fix it.

Record your assessment by calling EACH of the tools listed in the opening message. Do not describe the values in prose: only tool calls are recorded.

CVSS v3.1 base metrics (`write_cvss_score`): score strictly as the CVSS v3.1 specification defines them. Each parameter of the tool quotes the specification's definition of the metric and of each value: pick the value whose definition fits. The Base metrics represent the intrinsic characteristics of a vulnerability that are constant over time and across user environments. Rules from the specification and its User Guide:
- Determine the vulnerable component, and score attack_vector, attack_complexity, privileges_required and user_interaction relative to it.
- For a vulnerability in a library, score the reasonable worst-case implementation scenario: for example, if applications commonly pass untrusted network input to the vulnerable code, attack_vector is NETWORK.
- If a specific configuration is required for the attack to succeed, score assuming the vulnerable component is in that configuration, unless the configuration is unreasonable (e.g. it disables security features against the vendor's documented guidance). A non-default configuration does not by itself make attack_complexity HIGH.
- attack_complexity excludes user interaction; record that in user_interaction.
- scope is CHANGED only if the impacted component is managed by a different security authority than the vulnerable one.
- A crash that an attacker can trigger repeatedly is a total loss of availability: availability_impact HIGH.

CWE (`write_cwe`): the most specific CWE for the root cause. When `search_cwe` is available, NEVER guess a CWE number from memory: search with words describing the root cause, then `read_cwe` the best candidates, and record the one whose description fits. Prefer Base or Variant entries over Class or Pillar ones. Pass the entry's exact name along with its number. Well-known entries include `CWE-170` "Improper Null Termination", `CWE-787` "Out-of-bounds Write", `CWE-125` "Out-of-bounds Read", `CWE-190` "Integer Overflow or Wraparound", `CWE-416` "Use After Free", `CWE-295` "Improper Certificate Validation".

RULES:
- If unsure, record your best guess. Do not skip a tool.
- After every listed tool has succeeded, call `finish` with a one-sentence summary."#;

/// Instructions for rating the vulnerability under the project's policy.
pub const RATE: &str = r#"You are a security engineer. You rate the severity of a vulnerability under the project's security policy, given the commits that fix it.

Record the rating by calling `write_severity`. Do not describe it in prose: only tool calls are recorded.

Choose the level whose definition in the security policy fits best. The policy is the only basis for the rating: apply its definitions, scope, and examples as written, even where a generic scale such as CVSS would rate the vulnerability differently.

RULES:
- If unsure, record your best guess. Do not skip the tool.
- After `write_severity` has succeeded, call `finish` with a one-sentence summary."#;

/// Instructions for writing the description.
pub const DESCRIBE: &str = r#"You are a security engineer. You write the description of a vulnerability for a public CVE record.

STYLE:
- 2 to 4 sentences of plain prose, in one paragraph.
- No markdown, no headings, no lists, no code.
- Start with "A flaw was found in <project>."
- Then say which component or configuration is affected and what goes wrong, how an attacker can trigger it, and what the impact is.
- Do NOT mention commit hashes, file names, function names, line numbers, or the fix.
- Do NOT speculate beyond the facts given.

Reply with the description only. If you need more context, you may call `read_commit` or `read_file` first."#;

/// Instructions for writing the title.
pub const TITLE: &str = r#"You write the title of a CVE record.

The title is a short phrase under 80 characters, in the form "<impact> via <cause>", for example:
- authentication bypass via NUL character in username
- heap buffer overflow in DTLS fragment reassembly
- denial of service via crafted certificate

Do not include the project name. Reply with the title only, on a single line."#;

fn push_hints(text: &mut String, hints: Option<&str>) {
    if let Some(hints) = hints {
        text.push_str(&format!("\n\nHints:\n{hints}"));
    }
}

/// The opening message for finding the introducing commit.
pub fn affected_opening(project: &str, fixes: &str, blame: &str, hints: Option<&str>) -> String {
    let mut text = format!(
        "Project: {project}\n\n\
         Find the commit that introduced the vulnerability fixed by the following commit(s).\n\n\
         # Fix\n\n{fixes}\n\n\
         # Blame\n\nCommits that last changed the lines touched by the fix, \
         as of just before the fix:\n\n{blame}"
    );
    push_hints(&mut text, hints);
    text
}

/// The opening message for scoring.
pub fn score_opening(
    project: &str,
    fixes: &str,
    facts: &str,
    tools: &[&str],
    hints: Option<&str>,
) -> String {
    let mut text = format!(
        "Project: {project}\n\n\
         Assess the vulnerability fixed by the following commit(s). \
         Call these tools: {}.\n",
        tools
            .iter()
            .map(|tool| format!("`{tool}`"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    if !facts.is_empty() {
        text.push_str(&format!("\n# Known facts\n\n{facts}\n"));
    }
    text.push_str(&format!("\n# Fix\n\n{fixes}"));
    push_hints(&mut text, hints);
    text
}

/// The opening message for rating.
pub fn rate_opening(
    project: &str,
    fixes: &str,
    facts: &str,
    policy: Option<&str>,
    severity_levels: &[String],
    hints: Option<&str>,
) -> String {
    let mut text = format!(
        "Project: {project}\n\n\
         Rate the severity of the vulnerability fixed by the following commit(s) \
         under the security policy. Call `write_severity`. \
         The severity rating must be one of: {}.\n",
        severity_levels.join(", ")
    );
    if !facts.is_empty() {
        text.push_str(&format!("\n# Known facts\n\n{facts}\n"));
    }
    match policy {
        Some(policy) => text.push_str(&format!("\n# Security policy\n\n{}\n", policy.trim())),
        None => text.push_str(
            "\nThe project has no written security policy: \
             rate by the impact and ease of exploitation.\n",
        ),
    }
    text.push_str(&format!("\n# Fix\n\n{fixes}"));
    push_hints(&mut text, hints);
    text
}

/// The opening message for the description.
pub fn describe_opening(project: &str, fixes: &str, facts: &str, hints: Option<&str>) -> String {
    let mut text = format!(
        "Project: {project}\n\n\
         Write the CVE description of the vulnerability fixed by the following commit(s).\n\n\
         # Known facts\n\n{facts}\n\n# Fix\n\n{fixes}"
    );
    push_hints(&mut text, hints);
    text
}

/// The opening message for the title.
pub fn title_opening(description: &str, facts: &str) -> String {
    format!("Write the title for this vulnerability.\n\n{description}\n\n{facts}")
}

/// Clean up a model's prose: drop reasoning blocks, markdown, labels and
/// quotes that small models add despite being told not to.
pub fn clean_prose(text: &str) -> String {
    let mut text = text.to_string();
    while let (Some(start), Some(end)) = (text.find("<think>"), text.find("</think>")) {
        if end < start {
            break;
        }
        text.replace_range(start..end + "</think>".len(), "");
    }
    // A reasoning block whose opening tag the server swallowed.
    if let Some(end) = text.find("</think>") {
        text.replace_range(..end + "</think>".len(), "");
    }
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("```") && !line.starts_with('#'))
        .map(|line| line.trim_start_matches(['-', '*', ' ']))
        .collect();
    let text = lines.join("\n").replace("**", "").replace('`', "");
    let mut text = text.trim();
    for label in ["Description:", "Title:"] {
        if text
            .get(..label.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(label))
        {
            text = text[label.len()..].trim_start();
        }
    }
    let text = text.trim_matches(['"', '\'', '“', '”']).trim();
    // Collapse paragraphs: a CVE description is a single block of text.
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Reduce a model's reply to a one-line title.
pub fn clean_title(text: &str, project: &str) -> String {
    let text = clean_prose(text.lines().find(|l| !l.trim().is_empty()).unwrap_or(""));
    let text = if text
        .get(..project.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(project))
        && text[project.len()..].starts_with(':')
    {
        text[project.len() + 1..].trim().to_string()
    } else {
        text
    };
    text.trim_end_matches('.').trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasoning_and_markdown_are_dropped() {
        let reply = "<think>Let me see.\nOK.</think>\n\n**Description:** A flaw was found in gnutls.\n\nAn attacker can bypass authentication.";
        assert_eq!(
            clean_prose(reply),
            "A flaw was found in gnutls. An attacker can bypass authentication."
        );
    }

    #[test]
    fn an_unopened_reasoning_block_is_dropped() {
        assert_eq!(clean_prose("thinking...</think>A flaw."), "A flaw.");
    }

    #[test]
    fn titles_lose_project_and_period() {
        assert_eq!(
            clean_title(
                "\"GnuTLS: authentication bypass via NUL character in username.\"\nExplanation...",
                "gnutls"
            ),
            "authentication bypass via NUL character in username"
        );
    }
}
