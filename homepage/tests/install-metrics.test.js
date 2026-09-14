import assert from "node:assert/strict";
import test from "node:test";

import { onRequest } from "../functions/_middleware.js";

function requestContext({ path = "/install", method = "GET", status = 200 } = {}) {
  const bindings = [];
  const writes = [];
  const response = new Response("installer", { status });
  const database = {
    prepare() {
      return {
        bind(...values) {
          bindings.push(values);
          return { run: async () => {} };
        },
      };
    },
  };

  return {
    bindings,
    response,
    writes,
    context: {
      request: new Request(`https://nahguard.ai${path}`, { method }),
      env: { INSTALL_METRICS: database },
      next: async () => response,
      waitUntil(promise) {
        writes.push(promise);
      },
    },
  };
}

test("successful installer GETs preserve the asset response and record the platform", async () => {
  for (const [path, platform] of [
    ["/install", "unix"],
    ["/install.ps1", "windows"],
  ]) {
    const fixture = requestContext({ path });
    const response = await onRequest(fixture.context);

    assert.equal(response, fixture.response);
    assert.equal(fixture.writes.length, 1);
    await fixture.writes[0];
    assert.match(fixture.bindings[0][0], /^\d{4}-\d{2}-\d{2}$/);
    assert.equal(fixture.bindings[0][1], platform);
  }
});

test("non-GET, failed, and unrelated requests are not counted", async () => {
  for (const options of [
    { method: "HEAD" },
    { status: 404 },
    { path: "/docs/" },
  ]) {
    const fixture = requestContext(options);
    const response = await onRequest(fixture.context);

    assert.equal(response, fixture.response);
    assert.equal(fixture.writes.length, 0);
    assert.deepEqual(fixture.bindings, []);
  }
});
