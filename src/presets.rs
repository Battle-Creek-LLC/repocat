use anyhow::{anyhow, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Minimal,
    Standard,
    Strict,
}

impl Preset {
    pub fn template(self) -> &'static str {
        match self {
            Preset::Minimal => include_str!("templates/minimal.yml"),
            Preset::Standard => include_str!("templates/standard.yml"),
            Preset::Strict => include_str!("templates/strict.yml"),
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "minimal" => Ok(Preset::Minimal),
            "standard" => Ok(Preset::Standard),
            "strict" => Ok(Preset::Strict),
            other => Err(anyhow!(
                "unknown preset `{other}` (want minimal, standard, or strict)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        assert_eq!(Preset::parse("minimal").unwrap(), Preset::Minimal);
        assert_eq!(Preset::parse("standard").unwrap(), Preset::Standard);
        assert_eq!(Preset::parse("strict").unwrap(), Preset::Strict);
        assert!(Preset::parse("medium").is_err());
    }

    #[test]
    fn templates_carry_org_placeholder() {
        for p in [Preset::Minimal, Preset::Standard, Preset::Strict] {
            assert!(p.template().contains("{{ORG}}"), "{p:?} missing {{ORG}}");
        }
    }

    #[test]
    fn templates_parse_after_substitution() {
        // Each template, with {{ORG}} substituted, must parse as a valid Config.
        for p in [Preset::Minimal, Preset::Standard, Preset::Strict] {
            let yaml = p.template().replace("{{ORG}}", "ExampleOrg");
            // repos is empty in templates, so we test parsing directly without
            // going through config::load (which requires non-empty repos).
            let cfg: crate::config::Config = serde_yaml_ng::from_str(&yaml)
                .unwrap_or_else(|e| panic!("{p:?} failed to parse: {e}"));
            assert_eq!(cfg.org, "ExampleOrg");
            assert!(!cfg.defaults.is_empty(), "{p:?} defaults are empty");
        }
    }
}
