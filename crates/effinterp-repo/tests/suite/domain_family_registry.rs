//! Every effect domain must map to a real short selector family, and that
//! family must round-trip back to the domain, so a rendered resource in any
//! domain is a valid selector needle. Guards the cloud-family fallback bug and
//! any future domain added without a family token.

use effinterp_proto::{DOMAINS, selector_family};
use effinterp_repo::Selector;

#[test]
fn every_domain_maps_to_a_real_family_and_round_trips() {
    for domain in DOMAINS {
        let fam = selector_family(domain);
        assert_ne!(
            fam, "other",
            "domain {domain:?} has no short selector family (falls back to `other`)"
        );
        // The short family must parse as a selector and resolve back to this
        // exact domain (e.g. filesystem -> fs -> filesystem, cloud -> cloud).
        let sel = Selector::parse(&format!("{fam}:x")).unwrap_or_else(|e| {
            panic!("family {fam:?} for domain {domain:?} is not parseable: {e}")
        });
        assert_eq!(
            sel.domain(),
            domain,
            "family {fam:?} does not round-trip back to domain {domain:?} (got {:?})",
            sel.domain()
        );
    }
}
