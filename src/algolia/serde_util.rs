//! Shared serde helpers used across every `algolia::*` response module.
//!
//! BUG-ALX-EVENTS-NULLCOLL / BUG-ALX-ANALYTICS-NULLCOLL: `#[serde(default)]`
//! alone only substitutes a default value when a JSON key is ABSENT — it
//! does NOT rescue a key that is present with an explicit `null`. That
//! distinction bit this codebase three times: `AnalyticsStatusResponse.
//! updated_at` (fixed by switching to `Option<String>` — `Option<T>` has its
//! own built-in null-handling in serde, independent of `#[serde(default)]`),
//! and `TopSearchesResponse.searches`/`NoResultsResponse.searches`/every
//! collection field on `RawEvent`/`EventPayload` (a bare `Vec<T>`/`HashMap<K,
//! V>` — no such built-in null handling exists for those, since `null` does
//! not deserialize into an empty `Vec`/`HashMap` on its own).
//!
//! `null_as_default` closes that gap for any `T: Default` collection/map
//! field: pair it with `#[serde(default, deserialize_with =
//! "crate::algolia::serde_util::null_as_default")]` and the field tolerates
//! all three wire shapes a low/no-data Algolia response can send — key
//! absent, key present as `null`, key present with the real value — while
//! still rejecting a genuinely wrong-shaped value (a string/number/object
//! where an array/map was expected), which is a real parse failure, not a
//! null-vs-absent ambiguity.
use serde::{Deserialize, Deserializer};

pub fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[derive(Debug, serde::Deserialize)]
    struct Wrapper {
        #[serde(default, deserialize_with = "null_as_default")]
        items: Vec<String>,
        #[serde(default, deserialize_with = "null_as_default")]
        map: HashMap<String, String>,
    }

    #[test]
    fn null_becomes_default() {
        let v = json!({"items": null, "map": null});
        let w: Wrapper = serde_json::from_value(v).unwrap();
        assert!(w.items.is_empty());
        assert!(w.map.is_empty());
    }

    #[test]
    fn absent_becomes_default() {
        let v = json!({});
        let w: Wrapper = serde_json::from_value(v).unwrap();
        assert!(w.items.is_empty());
        assert!(w.map.is_empty());
    }

    #[test]
    fn real_value_passes_through() {
        let v = json!({"items": ["a", "b"], "map": {"k": "v"}});
        let w: Wrapper = serde_json::from_value(v).unwrap();
        assert_eq!(w.items, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(w.map.get("k"), Some(&"v".to_string()));
    }

    #[test]
    fn wrong_shape_still_rejected() {
        let v = json!({"items": "not an array", "map": null});
        let err = serde_json::from_value::<Wrapper>(v).unwrap_err();
        assert!(err.to_string().contains("invalid type"));
    }
}
