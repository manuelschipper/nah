import assert from "node:assert/strict";
import test from "node:test";

import { onRequest } from "../functions/_middleware.js";

function homepageFixture(t, github) {
  const entries = new Map();
  const rewrites = [];
  const errors = [];
  const requests = [];
  t.mock.method(globalThis, "fetch", github);
  t.mock.method(console, "error", (...args) => errors.push(args));
  globalThis.caches = {
    default: {
      async match(key) {
        return entries.get(key.url)?.clone();
      },
      async put(key, response) {
        entries.set(key.url, response);
      },
    },
  };
  globalThis.HTMLRewriter = class {
    on(selector, handler) {
      handler.element({
        setInnerContent(content) {
          rewrites.push({ selector, content });
        },
      });
      return this;
    }
    transform(response) {
      return response;
    }
  };
  t.after(() => {
    delete globalThis.caches;
    delete globalThis.HTMLRewriter;
  });

  return {
    entries,
    rewrites,
    errors,
    requests,
    async request(path = "/", {
      ifNoneMatch = '"old-static"', assetETag = '"static"', token,
    } = {}) {
      const pending = [];
      const response = await onRequest({
        request: new Request(`https://nahguard.ai${path}`, {
          headers: {
            "If-None-Match": ifNoneMatch,
            "If-Modified-Since": "Mon, 09 Nov 2026 00:00:00 GMT",
          },
        }),
        env: { GITHUB_TOKEN: token },
        next: async (request) => {
          requests.push(request);
          return new Response('<span id="open-issues">7 open</span>', {
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              ETag: assetETag,
              "Last-Modified": "Mon, 09 Nov 2026 00:00:00 GMT",
              "Cache-Control": "public, max-age=0, must-revalidate",
            },
          });
        },
        waitUntil(promise) {
          pending.push(promise);
        },
      });
      await Promise.all(pending);
      return response;
    },
  };
}

test("homepages share an issue-only count until the edge cache expires", async (t) => {
  let fetches = 0;
  const authorizations = [];
  const fixture = homepageFixture(t, async (url, options) => {
    const query = new URL(url).searchParams;
    assert.equal(query.get("q"), "repo:manuelschipper/nah type:issue state:open");
    assert.equal(query.get("per_page"), "1");
    assert.equal(options.headers["User-Agent"], "nahguard.ai");
    assert.ok(options.signal instanceof AbortSignal);
    authorizations.push(options.headers.Authorization);
    return Response.json({
      total_count: fetches++ === 0 ? 3 : 0, incomplete_results: false,
    });
  });

  for (const path of ["/", "/?campaign=example"]) {
    const response = await fixture.request(path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "public, max-age=0, must-revalidate");
    assert.equal(response.headers.get("ETag"), '"static-3"');
    assert.equal(response.headers.get("Last-Modified"), null);
    const request = fixture.requests.at(-1);
    assert.equal(request.headers.get("If-None-Match"), null);
    assert.equal(request.headers.get("If-Modified-Since"), null);
  }
  assert.equal(fetches, 1);
  assert.equal(fixture.entries.size, 1);
  assert.equal(
    [...fixture.entries.values()][0].headers.get("Cache-Control"),
    "public, max-age=1200",
  );

  for (const ifNoneMatch of ['"static-3"', 'W/"static-3"', '"other", "static-3"', "*"]) {
    const response = await fixture.request("/", { ifNoneMatch });
    assert.equal(response.status, 304);
    assert.equal(await response.text(), "");
    assert.equal(response.headers.get("ETag"), '"static-3"');
    assert.equal(response.headers.get("Cache-Control"), "public, max-age=0, must-revalidate");
    assert.equal(response.headers.get("Last-Modified"), null);
  }
  const changedAsset = await fixture.request("/", {
    ifNoneMatch: '"static-3"', assetETag: '"new-static"',
  });
  assert.equal(changedAsset.status, 200);
  assert.equal(changedAsset.headers.get("ETag"), '"new-static-3"');
  assert.equal(fetches, 1);

  // Cache API drops expired entries; the next visit must query GitHub again.
  fixture.entries.clear();
  const changedCount = await fixture.request("/", {
    ifNoneMatch: '"static-3"', token: "test-token",
  });
  assert.equal(changedCount.status, 200);
  assert.equal(changedCount.headers.get("ETag"), '"static-0"');
  assert.equal(fetches, 2);
  assert.deepEqual(authorizations, [undefined, "Bearer test-token"]);
  assert.deepEqual(fixture.rewrites, [
    { selector: "#open-issues", content: "3 open" },
    { selector: "#open-issues", content: "3 open" },
    { selector: "#open-issues", content: "3 open" },
    { selector: "#open-issues", content: "0 open" },
  ]);
  assert.deepEqual(fixture.errors, []);
});

test("GitHub failures are cached briefly while the baked page keeps revalidating", async (t) => {
  const results = [
    new Response("rate limited", { status: 403 }),
    new Response("unavailable", { status: 503 }),
    new Response("invalid JSON"),
    Response.json({ total_count: 1, incomplete_results: true }),
    Response.json({ total_count: -1 }),
    Response.json({ total_count: "1" }),
    Response.json({}),
    new Error("network unavailable"),
    new DOMException("request timed out", "TimeoutError"),
  ];
  const failures = results.length;
  results.push(Response.json({ total_count: 2 }));
  let fetches = 0;
  const fixture = homepageFixture(t, async () => {
    fetches++;
    const result = results.shift();
    if (result instanceof Error) throw result;
    return result;
  });
  for (let i = 0; i < failures; i++) {
    fixture.entries.clear();
    for (const path of ["/", "/?retry=1", "/?retry=2"]) {
      const response = await fixture.request(path);
      assert.equal(response.status, 200);
      assert.match(await response.text(), />7 open</);
      assert.equal(response.headers.get("ETag"), '"static"');
      assert.equal(response.headers.get("Cache-Control"), "public, max-age=0, must-revalidate");
      assert.equal(response.headers.get("Last-Modified"), null);
    }
    const unchanged = await fixture.request("/", { ifNoneMatch: '"static"' });
    assert.equal(unchanged.status, 304);
    assert.equal(await unchanged.text(), "");
    assert.equal(unchanged.headers.get("ETag"), '"static"');
    assert.equal(fetches, i + 1);
    assert.equal(fixture.entries.size, 1);
    assert.equal(
      [...fixture.entries.values()][0].headers.get("Cache-Control"),
      "public, max-age=120",
    );
  }
  assert.deepEqual(fixture.rewrites, []);
  assert.equal(fixture.errors.length, failures);

  fixture.entries.clear();
  const recovered = await fixture.request("/", { ifNoneMatch: '"static"' });
  assert.equal(recovered.status, 200);
  assert.equal(recovered.headers.get("ETag"), '"static-2"');
  assert.equal(fetches, failures + 1);
  assert.deepEqual(fixture.rewrites, [{ selector: "#open-issues", content: "2 open" }]);
});
