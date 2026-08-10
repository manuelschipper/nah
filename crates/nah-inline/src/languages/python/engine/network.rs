//! Requests, HTTPX, and urllib network call shapes.

use super::*;

pub(super) fn request_callable(kind: RequestKind) -> &'static str {
    match kind {
        RequestKind::RequestsGet => "requests.get",
        RequestKind::RequestsPost => "requests.post",
        RequestKind::RequestsPut => "requests.put",
        RequestKind::RequestsPatch => "requests.patch",
        RequestKind::RequestsDelete => "requests.delete",
        RequestKind::HttpxGet => "httpx.get",
        RequestKind::HttpxPost => "httpx.post",
        RequestKind::HttpxPut => "httpx.put",
        RequestKind::HttpxPatch => "httpx.patch",
        RequestKind::HttpxDelete => "httpx.delete",
        RequestKind::UrlOpen => "urllib.request.urlopen",
        RequestKind::UrlRetrieve => "urllib.request.urlretrieve",
    }
}

pub(super) fn request_url_keyword(kind: RequestKind) -> &'static str {
    match kind {
        RequestKind::RequestsGet
        | RequestKind::RequestsPost
        | RequestKind::RequestsPut
        | RequestKind::RequestsPatch
        | RequestKind::RequestsDelete
        | RequestKind::HttpxGet
        | RequestKind::HttpxPost
        | RequestKind::HttpxPut
        | RequestKind::HttpxPatch
        | RequestKind::HttpxDelete => "url",
        RequestKind::UrlOpen | RequestKind::UrlRetrieve => "url",
    }
}

pub(super) fn request_call_shape(
    kind: RequestKind,
    arguments: &Arguments,
    program: &str,
) -> CallShape {
    const REQUESTS_COMMON: &[&str] = &[
        "params",
        "data",
        "headers",
        "cookies",
        "files",
        "auth",
        "timeout",
        "allow_redirects",
        "proxies",
        "hooks",
        "stream",
        "verify",
        "cert",
        "json",
    ];
    const HTTPX_COMMON: &[&str] = &[
        "params",
        "headers",
        "cookies",
        "auth",
        "proxy",
        "proxies",
        "follow_redirects",
        "cert",
        "verify",
        "timeout",
        "trust_env",
    ];
    const HTTPX_BODY: &[&str] = &[
        "content",
        "data",
        "files",
        "json",
        "params",
        "headers",
        "cookies",
        "auth",
        "proxy",
        "proxies",
        "follow_redirects",
        "cert",
        "verify",
        "timeout",
        "trust_env",
    ];
    match kind {
        RequestKind::RequestsGet => {
            call_shape(arguments, 1, &["url", "params"], 0, REQUESTS_COMMON)
        }
        RequestKind::RequestsPost => {
            call_shape(arguments, 1, &["url", "data", "json"], 0, REQUESTS_COMMON)
        }
        RequestKind::RequestsPut | RequestKind::RequestsPatch => {
            call_shape(arguments, 1, &["url", "data"], 0, REQUESTS_COMMON)
        }
        RequestKind::RequestsDelete => call_shape(arguments, 1, &["url"], 0, REQUESTS_COMMON),
        RequestKind::HttpxGet | RequestKind::HttpxDelete => {
            call_shape(arguments, 1, &["url"], 0, HTTPX_COMMON)
        }
        RequestKind::HttpxPost | RequestKind::HttpxPut | RequestKind::HttpxPatch => {
            call_shape(arguments, 1, &["url"], 0, HTTPX_BODY)
        }
        RequestKind::UrlOpen => {
            let keywords = match python3_minor(program) {
                Some(0 | 1) => &[] as &[_],
                Some(2) => &["cafile", "capath"] as &[_],
                Some(3) => &["cafile", "capath", "cadefault"] as &[_],
                Some(13..) => &["context"] as &[_],
                Some(4..=12) | None => &["cafile", "capath", "cadefault", "context"] as &[_],
            };
            call_shape(arguments, 1, &["url", "data", "timeout"], 0, keywords)
        }
        RequestKind::UrlRetrieve => call_shape(
            arguments,
            1,
            &["url", "filename", "reporthook", "data"],
            0,
            &[],
        ),
    }
}
