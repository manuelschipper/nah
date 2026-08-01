use super::support::{init_repo, request, value};
use crate::fulfill;
use nah_proto::observation::{ObservationFailure, ObservationValue, Observed, RootKind};

#[test]
fn uses_requested_cwd_instead_of_process_cwd() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("requested");
    init_repo(&repo);

    let observation = fulfill(&request(&repo, &[])).expect("observation");

    let ObservationValue::Cwd {
        observed: Observed::Ok { value: cwd },
    } = value(&observation, "cwd")
    else {
        panic!("expected observed cwd");
    };
    assert_eq!(cwd.as_str(), repo.canonicalize().unwrap().to_str().unwrap());

    let ObservationValue::Roots {
        observed: Observed::Ok { value: roots },
    } = value(&observation, "roots")
    else {
        panic!("expected roots");
    };
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].kind(), RootKind::Project);
    assert_eq!(
        roots[0].path().as_str(),
        repo.canonicalize().unwrap().to_str().unwrap()
    );
}

#[test]
fn missing_requested_cwd_is_observed_without_using_ambient_cwd() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing");

    let observation = fulfill(&request(&missing, &[("path", "child")])).expect("observation");

    assert!(matches!(
        value(&observation, "cwd"),
        ObservationValue::Cwd {
            observed: Observed::Error {
                error: ObservationFailure::NotFound
            }
        }
    ));
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::NotFound
            }
        }
    ));
    assert!(matches!(
        value(&observation, "path"),
        ObservationValue::Path {
            observed: Observed::Error {
                error: ObservationFailure::NotFound
            }
        }
    ));
}
