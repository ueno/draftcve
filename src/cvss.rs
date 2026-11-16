//! CVSS v3.1 base metrics, scored per the specification.
//!
//! The model only picks the eight metric values. Arithmetic and the vector
//! string are ours: a small model gets either wrong more often than not.
//!
//! The documentation of each metric and value is the help text of the FIRST
//! calculator at <https://www.first.org/cvss/calculator/cvsscalc31_helptext.js>,
//! which summarizes the CVSS v3.1 Specification Document. It is given to the
//! model as the definition of each value, so edit it with care. It is under
//! the following license, also in `LICENSE-FIRST`:
//!
//! Copyright (c) 2019, FIRST.ORG, INC.
//! All rights reserved.
//!
//! Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//! following conditions are met:
//! 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//! disclaimer.
//! 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//! following disclaimer in the documentation and/or other materials provided with the distribution.
//! 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//! products derived from this software without specific prior written permission.
//!
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//! INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//! DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//! SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//! SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//! WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//! OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use anyhow::{Result, bail};
use serde_json::{Value, json};

/// A metric, with its help text.
///
/// Names are spelled from the enum's: `AttackVector` is `attackVector` in the
/// CVE schema and `attack_vector` in the tool parameters.
pub struct MetricInfo {
    /// Abbreviation in the vector string, e.g. `AV`.
    pub key: &'static str,
    /// The enum's name, e.g. `AttackVector`.
    ident: &'static str,
    help: &'static str,
    /// In the order the metric's enum declares them.
    pub values: &'static [ValueInfo],
}

/// A value of a metric, with its help text.
pub struct ValueInfo {
    /// Abbreviation in the vector string, e.g. `N`.
    pub abbreviation: char,
    /// The variant's name, e.g. `AdjacentNetwork`.
    ident: &'static str,
    help: &'static str,
}

impl MetricInfo {
    /// Name in the CVE schema, e.g. `attackVector`.
    pub fn name(&self) -> String {
        words(self.ident)
            .enumerate()
            .map(|(index, word)| match index {
                0 => word.to_ascii_lowercase(),
                _ => word.to_string(),
            })
            .collect()
    }

    /// Name of the tool parameter, e.g. `attack_vector`.
    pub fn param(&self) -> String {
        let words: Vec<_> = words(self.ident).map(str::to_ascii_lowercase).collect();
        words.join("_")
    }

    pub fn help(&self) -> String {
        unwrap_doc(self.help)
    }
}

impl ValueInfo {
    /// Name in the CVE schema, e.g. `ADJACENT_NETWORK`.
    pub fn name(&self) -> String {
        let words: Vec<_> = words(self.ident).map(str::to_ascii_uppercase).collect();
        words.join("_")
    }

    pub fn help(&self) -> String {
        unwrap_doc(self.help)
    }
}

/// Split a Rust type or variant name into words: `AdjacentNetwork` into
/// `Adjacent` and `Network`.
fn words(ident: &str) -> impl Iterator<Item = &str> {
    let mut rest = ident;
    std::iter::from_fn(move || {
        let first = rest.chars().next()?;
        let end = rest[first.len_utf8()..]
            .find(|c: char| c.is_ascii_uppercase())
            .map_or(rest.len(), |index| index + first.len_utf8());
        let (word, tail) = rest.split_at(end);
        rest = tail;
        Some(word)
    })
}

/// Join the lines of a doc comment back into one paragraph.
fn unwrap_doc(doc: &str) -> String {
    doc.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A base metric, as an enum of its values.
pub trait Metric: Copy + 'static {
    const INFO: &'static MetricInfo;
    /// Every value, in the order of `INFO.values`.
    const ALL: &'static [Self];

    fn info(self) -> &'static ValueInfo;
}

/// Define a metric's enum, taking the help texts from its doc comments and
/// the names from its identifiers, with the abbreviations of the vector:
///
/// ```ignore
/// metric! {
///     /// Help for the metric.
///     AttackVector("AV") {
///         /// Help for the value.
///         AdjacentNetwork('A'),
///     }
/// }
/// ```
macro_rules! metric {
    (
        $(#[doc = $doc:literal])*
        $metric:ident($key:literal) {
            $(
                $(#[doc = $value_doc:literal])*
                $value:ident($abbreviation:literal),
            )+
        }
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $metric {
            $(
                $(#[doc = $value_doc])*
                $value,
            )+
        }

        impl Metric for $metric {
            const INFO: &'static MetricInfo = &MetricInfo {
                key: $key,
                ident: stringify!($metric),
                help: concat!($($doc, "\n"),*),
                values: &[$(
                    ValueInfo {
                        abbreviation: $abbreviation,
                        ident: stringify!($value),
                        help: concat!($($value_doc, "\n"),*),
                    },
                )+],
            };
            const ALL: &'static [Self] = &[$(Self::$value),+];

            fn info(self) -> &'static ValueInfo {
                &Self::INFO.values[self as usize]
            }
        }
    };
}

metric! {
    /// This metric reflects the context by which vulnerability exploitation is
    /// possible. The Base Score increases the more remote (logically, and
    /// physically) an attacker can be in order to exploit the vulnerable
    /// component.
    AttackVector("AV") {
        /// The vulnerable component is bound to the network stack and the set
        /// of possible attackers extends beyond the other options listed, up to
        /// and including the entire Internet. Such a vulnerability is often
        /// termed 'remotely exploitable' and can be thought of as an attack
        /// being exploitable at the protocol level one or more network hops
        /// away (e.g., across one or more routers).
        Network('N'),
        /// The vulnerable component is bound to the network stack, but the
        /// attack is limited at the protocol level to a logically adjacent
        /// topology. This can mean an attack must be launched from the same
        /// shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g.,
        /// local IP subnet) network, or from within a secure or otherwise
        /// limited administrative domain (e.g., MPLS, secure VPN to an
        /// administrative network zone).
        AdjacentNetwork('A'),
        /// The vulnerable component is not bound to the network stack and the
        /// attacker’s path is via read/write/execute capabilities. Either: the
        /// attacker exploits the vulnerability by accessing the target system
        /// locally (e.g., keyboard, console), or remotely (e.g., SSH); or the
        /// attacker relies on User Interaction by another person to perform
        /// actions required to exploit the vulnerability (e.g., tricking a
        /// legitimate user into opening a malicious document).
        Local('L'),
        /// The attack requires the attacker to physically touch or manipulate
        /// the vulnerable component. Physical interaction may be brief or
        /// persistent.
        Physical('P'),
    }
}

metric! {
    /// This metric describes the conditions beyond the attacker’s control that
    /// must exist in order to exploit the vulnerability. Such conditions may
    /// require the collection of more information about the target or
    /// computational exceptions. The assessment of this metric excludes any
    /// requirements for user interaction in order to exploit the vulnerability.
    /// If a specific configuration is required for an attack to succeed, the
    /// Base metrics should be scored assuming the vulnerable component is in
    /// that configuration.
    AttackComplexity("AC") {
        /// Specialized access conditions or extenuating circumstances do not
        /// exist. An attacker can expect repeatable success against the
        /// vulnerable component.
        Low('L'),
        /// A successful attack depends on conditions beyond the attacker's
        /// control. That is, a successful attack cannot be accomplished at
        /// will, but requires the attacker to invest in some measurable amount
        /// of effort in preparation or execution against the vulnerable
        /// component before a successful attack can be expected. For example, a
        /// successful attack may require an attacker to: gather knowledge about
        /// the environment in which the vulnerable target/component exists;
        /// prepare the target environment to improve exploit reliability; or
        /// inject themselves into the logical network path between the target
        /// and the resource requested by the victim in order to read and/or
        /// modify network communications (e.g., a man in the middle attack).
        High('H'),
    }
}

metric! {
    /// This metric describes the level of privileges an attacker must possess
    /// before successfully exploiting the vulnerability.
    PrivilegesRequired("PR") {
        /// The attacker is unauthorized prior to attack, and therefore does not
        /// require any access to settings or files to carry out an attack.
        None('N'),
        /// The attacker is authorized with (i.e., requires) privileges that
        /// provide basic user capabilities that could normally affect only
        /// settings and files owned by a user. Alternatively, an attacker with
        /// Low privileges may have the ability to cause an impact only to
        /// non-sensitive resources.
        Low('L'),
        /// The attacker is authorized with (i.e., requires) privileges that
        /// provide significant (e.g., administrative) control over the
        /// vulnerable component that could affect component-wide settings and
        /// files.
        High('H'),
    }
}

metric! {
    /// This metric captures the requirement for a user, other than the
    /// attacker, to participate in the successful compromise the vulnerable
    /// component. This metric determines whether the vulnerability can be
    /// exploited solely at the will of the attacker, or whether a separate user
    /// (or user-initiated process) must participate in some manner.
    UserInteraction("UI") {
        /// The vulnerable system can be exploited without any interaction from
        /// any user.
        None('N'),
        /// Successful exploitation of this vulnerability requires a user to
        /// take some action before the vulnerability can be exploited.
        Required('R'),
    }
}

metric! {
    /// Does a successful attack impact a component other than the vulnerable
    /// component? If so, the Base Score increases and the Confidentiality,
    /// Integrity and Authentication metrics should be scored relative to the
    /// impacted component.
    Scope("S") {
        /// An exploited vulnerability can only affect resources managed by the
        /// same security authority. In this case, the vulnerable component and
        /// the impacted component are either the same, or both are managed by
        /// the same security authority.
        Unchanged('U'),
        /// An exploited vulnerability can affect resources beyond the security
        /// scope managed by the security authority of the vulnerable component.
        /// In this case, the vulnerable component and the impacted component
        /// are different and managed by different security authorities.
        Changed('C'),
    }
}

metric! {
    /// This metric measures the impact to the confidentiality of the
    /// information resources managed by a software component due to a
    /// successfully exploited vulnerability. Confidentiality refers to limiting
    /// information access and disclosure to only authorized users, as well as
    /// preventing access by, or disclosure to, unauthorized ones.
    ConfidentialityImpact("C") {
        /// There is no loss of confidentiality within the impacted component.
        None('N'),
        /// There is some loss of confidentiality. Access to some restricted
        /// information is obtained, but the attacker does not have control over
        /// what information is obtained, or the amount or kind of loss is
        /// limited. The information disclosure does not cause a direct, serious
        /// loss to the impacted component.
        Low('L'),
        /// There is total loss of confidentiality, resulting in all resources
        /// within the impacted component being divulged to the attacker.
        /// Alternatively, access to only some restricted information is
        /// obtained, but the disclosed information presents a direct, serious
        /// impact.
        High('H'),
    }
}

metric! {
    /// This metric measures the impact to integrity of a successfully exploited
    /// vulnerability. Integrity refers to the trustworthiness and veracity of
    /// information.
    IntegrityImpact("I") {
        /// There is no loss of integrity within the impacted component.
        None('N'),
        /// Modification of data is possible, but the attacker does not have
        /// control over the consequence of a modification, or the amount of
        /// modification is limited. The data modification does not have a
        /// direct, serious impact on the impacted component.
        Low('L'),
        /// There is a total loss of integrity, or a complete loss of
        /// protection. For example, the attacker is able to modify any/all
        /// files protected by the impacted component. Alternatively, only some
        /// files can be modified, but malicious modification would present a
        /// direct, serious consequence to the impacted component.
        High('H'),
    }
}

metric! {
    /// This metric measures the impact to the availability of the impacted
    /// component resulting from a successfully exploited vulnerability. It
    /// refers to the loss of availability of the impacted component itself,
    /// such as a networked service (e.g., web, database, email). Since
    /// availability refers to the accessibility of information resources,
    /// attacks that consume network bandwidth, processor cycles, or disk space
    /// all impact the availability of an impacted component.
    AvailabilityImpact("A") {
        /// There is no impact to availability within the impacted component.
        None('N'),
        /// Performance is reduced or there are interruptions in resource
        /// availability. Even if repeated exploitation of the vulnerability is
        /// possible, the attacker does not have the ability to completely deny
        /// service to legitimate users. The resources in the impacted component
        /// are either partially available all of the time, or fully available
        /// only some of the time, but overall there is no direct, serious
        /// consequence to the impacted component.
        Low('L'),
        /// There is total loss of availability, resulting in the attacker being
        /// able to fully deny access to resources in the impacted component;
        /// this loss is either sustained (while the attacker continues to
        /// deliver the attack) or persistent (the condition persists even after
        /// the attack has completed). Alternatively, the attacker has the
        /// ability to deny some availability, but the loss of availability
        /// presents a direct, serious consequence to the impacted component
        /// (e.g., the attacker cannot disrupt existing connections, but can
        /// prevent new connections; the attacker can repeatedly exploit a
        /// vulnerability that, in each instance of a successful attack, leaks a
        /// only small amount of memory, but after repeated exploitation causes
        /// a service to become completely unavailable).
        High('H'),
    }
}
/// The metrics, in the order of the vector string.
const METRICS: [&MetricInfo; 8] = [
    AttackVector::INFO,
    AttackComplexity::INFO,
    PrivilegesRequired::INFO,
    UserInteraction::INFO,
    Scope::INFO,
    ConfidentialityImpact::INFO,
    IntegrityImpact::INFO,
    AvailabilityImpact::INFO,
];

/// Describe each metric of a `write_cvss_score` schema with FIRST's help
/// text, so the model reads the specification's definition of every value
/// right where it picks one.
pub fn describe_params(properties: &mut serde_json::Map<String, Value>) {
    for metric in METRICS {
        let Some(property) = properties
            .get_mut(&metric.param())
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let mut text = metric.help();
        for value in metric.values {
            text.push_str(&format!("\n{}: {}", value.name(), value.help()));
        }
        property.insert("description".to_string(), Value::String(text));
    }
}

/// Base metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cvss {
    attack_vector: AttackVector,
    attack_complexity: AttackComplexity,
    privileges_required: PrivilegesRequired,
    user_interaction: UserInteraction,
    scope: Scope,
    confidentiality: ConfidentialityImpact,
    integrity: IntegrityImpact,
    availability: AvailabilityImpact,
}

impl Cvss {
    /// Parse `CVSS:3.1/AV:N/AC:L/...`. The metrics may come in any order.
    pub fn parse_vector(vector: &str) -> Result<Self> {
        let mut parts = vector.trim().split('/');
        match parts.next() {
            Some("CVSS:3.1") => {}
            Some(other) => bail!("unsupported CVSS version `{other}`; expected `CVSS:3.1`"),
            None => bail!("empty CVSS vector"),
        }
        let mut values = [None; 8];
        for part in parts {
            let Some((key, value)) = part.split_once(':') else {
                bail!("malformed CVSS metric `{part}`");
            };
            let Some(index) = METRICS.iter().position(|metric| metric.key == key) else {
                bail!("unknown CVSS base metric `{key}`");
            };
            values[index] = Some(lenient(METRICS[index], value)?);
        }
        Self::from_options(values)
    }

    /// Build from metric values keyed by schema name (`attackVector`, ...), or
    /// by snake case (`attack_vector`). Values are accepted in either full or
    /// abbreviated form, in any case.
    pub fn from_named(named: &serde_json::Map<String, Value>) -> Result<Self> {
        let mut values = [None; 8];
        for (index, metric) in METRICS.iter().enumerate() {
            let value = named
                .get(&metric.name())
                .or_else(|| named.get(&metric.param()))
                .and_then(Value::as_str);
            if let Some(value) = value {
                values[index] = Some(lenient(metric, value)?);
            }
        }
        Self::from_options(values)
    }

    /// Build from the index of each metric's value, in `METRICS` order.
    fn from_options(values: [Option<usize>; 8]) -> Result<Self> {
        let missing: Vec<_> = METRICS
            .iter()
            .zip(values)
            .filter(|(_, value)| value.is_none())
            .map(|(metric, _)| metric.param())
            .collect();
        if !missing.is_empty() {
            bail!("missing CVSS metrics: {}", missing.join(", "));
        }
        Ok(Self {
            attack_vector: pick(&values),
            attack_complexity: pick(&values),
            privileges_required: pick(&values),
            user_interaction: pick(&values),
            scope: pick(&values),
            confidentiality: pick(&values),
            integrity: pick(&values),
            availability: pick(&values),
        })
    }

    /// Each metric's value, in `METRICS` order.
    fn values(&self) -> [&'static ValueInfo; 8] {
        [
            self.attack_vector.info(),
            self.attack_complexity.info(),
            self.privileges_required.info(),
            self.user_interaction.info(),
            self.scope.info(),
            self.confidentiality.info(),
            self.integrity.info(),
            self.availability.info(),
        ]
    }

    pub fn vector(&self) -> String {
        let metrics: Vec<_> = METRICS
            .iter()
            .zip(self.values())
            .map(|(metric, value)| format!("{}:{}", metric.key, value.abbreviation))
            .collect();
        format!("CVSS:3.1/{}", metrics.join("/"))
    }

    pub fn base_score(&self) -> f64 {
        let changed = self.scope == Scope::Changed;
        let av = match self.attack_vector {
            AttackVector::Network => 0.85,
            AttackVector::AdjacentNetwork => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        };
        let ac = match self.attack_complexity {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        };
        let pr = match (self.privileges_required, changed) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, false) => 0.62,
            (PrivilegesRequired::Low, true) => 0.68,
            (PrivilegesRequired::High, false) => 0.27,
            (PrivilegesRequired::High, true) => 0.5,
        };
        let ui = match self.user_interaction {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        };
        let c = match self.confidentiality {
            ConfidentialityImpact::None => 0.0,
            ConfidentialityImpact::Low => 0.22,
            ConfidentialityImpact::High => 0.56,
        };
        let i = match self.integrity {
            IntegrityImpact::None => 0.0,
            IntegrityImpact::Low => 0.22,
            IntegrityImpact::High => 0.56,
        };
        let a = match self.availability {
            AvailabilityImpact::None => 0.0,
            AvailabilityImpact::Low => 0.22,
            AvailabilityImpact::High => 0.56,
        };
        let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
        let impact = if changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
        } else {
            6.42 * iss
        };
        let exploitability = 8.22 * av * ac * pr * ui;
        if impact <= 0.0 {
            0.0
        } else if changed {
            roundup((1.08 * (impact + exploitability)).min(10.0))
        } else {
            roundup((impact + exploitability).min(10.0))
        }
    }

    pub fn base_severity(&self) -> &'static str {
        severity(self.base_score())
    }

    /// The `cvssV3_1` object as the CVE schema defines it.
    pub fn to_json(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("version".into(), json!("3.1"));
        object.insert("vectorString".into(), json!(self.vector()));
        object.insert("baseScore".into(), json!(self.base_score()));
        object.insert("baseSeverity".into(), json!(self.base_severity()));
        for (metric, value) in METRICS.iter().zip(self.values()) {
            object.insert(metric.name(), json!(value.name()));
        }
        Value::Object(object)
    }
}

/// The value of metric `M`, from value indices in `METRICS` order.
fn pick<M: Metric>(values: &[Option<usize>; 8]) -> M {
    let index = METRICS
        .iter()
        .position(|metric| metric.key == M::INFO.key)
        .expect("every metric is in METRICS");
    M::ALL[values[index].expect("missing metrics are rejected first")]
}

pub fn severity(score: f64) -> &'static str {
    match score {
        s if s == 0.0 => "NONE",
        s if s < 4.0 => "LOW",
        s if s < 7.0 => "MEDIUM",
        s if s < 9.0 => "HIGH",
        _ => "CRITICAL",
    }
}

/// Round up to one decimal, avoiding floating point surprises as the
/// specification's Appendix A prescribes.
fn roundup(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
    }
}

/// Accept `N`, `network`, `Network`, `ADJACENT`, `adjacent network`, ...
/// Returns the index of the value in `metric.values`.
fn lenient(metric: &MetricInfo, value: &str) -> Result<usize> {
    let normalized: String = value
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    for (index, candidate) in metric.values.iter().enumerate() {
        if normalized.is_empty() {
            break;
        }
        let name = candidate.name();
        if normalized.chars().eq([candidate.abbreviation])
            || normalized == name
            || name.starts_with(&normalized)
        {
            return Ok(index);
        }
    }
    let allowed: Vec<_> = metric.values.iter().map(ValueInfo::name).collect();
    bail!(
        "invalid value `{value}` for {}; expected one of {}",
        metric.param(),
        allowed.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_the_gnutls_example() {
        let cvss = Cvss::parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N").unwrap();
        assert_eq!(cvss.base_score(), 7.1);
        assert_eq!(cvss.base_severity(), "HIGH");
    }

    #[test]
    fn scores_known_vectors() {
        for (vector, score) in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ] {
            let cvss = Cvss::parse_vector(vector).unwrap();
            assert_eq!(cvss.base_score(), score, "{vector}");
            assert_eq!(cvss.vector(), vector);
        }
    }

    #[test]
    fn named_values_are_lenient() {
        let named = json!({
            "attack_vector": "network",
            "attack_complexity": "L",
            "privileges_required": "low",
            "user_interaction": "None",
            "scope": "unchanged",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "low",
            "availability_impact": "none",
        });
        let cvss = Cvss::from_named(named.as_object().unwrap()).unwrap();
        assert_eq!(
            cvss.vector(),
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
        );
        assert_eq!(cvss.to_json()["attackVector"], "NETWORK");
    }

    #[test]
    fn missing_metrics_are_named() {
        let named = json!({"attack_vector": "NETWORK"});
        let error = Cvss::from_named(named.as_object().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("scope"), "{error}");
    }

    #[test]
    fn invalid_values_list_the_choices() {
        let error = Cvss::parse_vector("CVSS:3.1/AV:X/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N")
            .unwrap_err()
            .to_string();
        assert!(error.contains("PHYSICAL"), "{error}");
    }

    #[test]
    fn doc_comments_are_the_help() {
        assert_eq!(unwrap_doc(" one\n two\n"), "one two");
        assert_eq!(
            Scope::Unchanged.info().help(),
            "An exploited vulnerability can only affect resources managed by the same \
             security authority. In this case, the vulnerable component and the impacted \
             component are either the same, or both are managed by the same security authority."
        );
        for metric in METRICS {
            assert!(!metric.help().is_empty(), "{} has no help", metric.key);
            for value in metric.values {
                let help = value.help();
                assert!(
                    !help.is_empty(),
                    "{}:{} has no help",
                    metric.key,
                    value.abbreviation
                );
                assert!(
                    !help.contains("  "),
                    "{}:{} is misjoined",
                    metric.key,
                    value.abbreviation
                );
            }
        }
    }

    #[test]
    fn enum_order_matches_the_value_table() {
        fn check<M: Metric + std::fmt::Debug>() {
            assert_eq!(M::ALL.len(), M::INFO.values.len());
            for (index, value) in M::ALL.iter().enumerate() {
                let expected = M::INFO.values[index].abbreviation;
                assert_eq!(value.info().abbreviation, expected, "{value:?}");
            }
        }
        check::<AttackVector>();
        check::<AttackComplexity>();
        check::<PrivilegesRequired>();
        check::<UserInteraction>();
        check::<Scope>();
        check::<ConfidentialityImpact>();
        check::<IntegrityImpact>();
        check::<AvailabilityImpact>();
    }

    #[test]
    fn names_are_spelled_from_identifiers() {
        let metric = AttackVector::INFO;
        assert_eq!(metric.name(), "attackVector");
        assert_eq!(metric.param(), "attack_vector");
        assert_eq!(
            AttackVector::AdjacentNetwork.info().name(),
            "ADJACENT_NETWORK"
        );
        assert_eq!(Scope::INFO.name(), "scope");
        assert_eq!(Scope::INFO.param(), "scope");
        let names: Vec<_> = METRICS.iter().map(|metric| metric.name()).collect();
        assert_eq!(
            names,
            [
                "attackVector",
                "attackComplexity",
                "privilegesRequired",
                "userInteraction",
                "scope",
                "confidentialityImpact",
                "integrityImpact",
                "availabilityImpact",
            ]
        );
    }
}
