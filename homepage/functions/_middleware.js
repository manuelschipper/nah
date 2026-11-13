const INSTALLERS = new Map([
  ["/install", "unix"],
  ["/install.ps1", "windows"],
]);

const UPSERT_INSTALLER_FETCH = `
  INSERT INTO installer_fetches (day, platform, fetches)
  VALUES (?, ?, 1)
  ON CONFLICT (day, platform)
  DO UPDATE SET fetches = fetches + 1
`;

async function recordInstallerFetch(database, day, platform) {
  await database.prepare(UPSERT_INSTALLER_FETCH).bind(day, platform).run();
}

async function refreshIssueCount(context, response) {
  // Share one count across homepage query strings at this edge.
  const key = new Request(new URL("/_open-issues-count", context.request.url));
  let issues = "";
  try {
    let count = await caches.default.match(key);
    if (!count) {
      const result = await fetch(
        "https://api.github.com/search/issues?q=repo:manuelschipper/nah" +
          "+type:issue+state:open&per_page=1",
        {
          headers: {
            Accept: "application/vnd.github+json",
            "User-Agent": "nahguard.ai",
            ...(context.env.GITHUB_TOKEN
              ? { Authorization: `Bearer ${context.env.GITHUB_TOKEN}` }
              : {}),
          },
          signal: AbortSignal.timeout(2000),
        },
      );
      if (!result.ok) throw new Error(`GitHub returned ${result.status}`);
      const { total_count, incomplete_results } = await result.json();
      if (
        !Number.isSafeInteger(total_count) || total_count < 0 || incomplete_results
      ) {
        throw new Error("GitHub returned an invalid issue count");
      }
      count = new Response(String(total_count), {
        headers: { "Cache-Control": "public, max-age=1200" },
      });
      context.waitUntil(
        caches.default.put(key, count.clone()).catch(
          (error) => console.error("failed to cache issue count", error),
        ),
      );
    }
    issues = await count.text();
  } catch (error) {
    console.error("failed to refresh issue count; using baked count", error);
    // An empty marker keeps the baked count without retrying GitHub.
    context.waitUntil(
      caches.default.put(key, new Response("", {
        headers: { "Cache-Control": "public, max-age=120" },
      })).catch((error) => console.error("failed to cache issue count", error)),
    );
  }

  const assetETag = response.headers.get("ETag");
  const etag = issues && assetETag
    ? assetETag.replace(/"$/, `-${issues}"`)
    : assetETag;
  response = new Response(response.body, response);
  if (etag) response.headers.set("ETag", etag);
  response.headers.delete("Last-Modified");
  response.headers.delete("Content-Length");

  const ifNoneMatch = context.request.headers.get("If-None-Match");
  if (etag && ifNoneMatch?.split(",").some((value) =>
    value.trim() === "*" || value.trim().replace(/^W\//, "") === etag.replace(/^W\//, "")
  )) {
    await response.body?.cancel();
    return new Response(null, { status: 304, headers: response.headers });
  }

  if (issues) {
    response = new HTMLRewriter()
      .on("#open-issues", {
        element(element) {
          element.setInnerContent(`${issues} open`);
        },
      })
      .transform(response);
  }
  return response;
}

export async function onRequest(context) {
  const path = new URL(context.request.url).pathname;
  const homepage = context.request.method === "GET" && path === "/";
  let request = context.request;
  if (homepage) {
    request = new Request(request);
    request.headers.delete("If-None-Match");
    request.headers.delete("If-Modified-Since");
  }
  const response = await context.next(request);
  const platform = INSTALLERS.get(path);

  if (context.request.method === "GET" && response.ok && platform) {
    const day = new Date().toISOString().slice(0, 10);
    context.waitUntil(
      recordInstallerFetch(context.env.INSTALL_METRICS, day, platform).catch(
        (error) => console.error("failed to record installer fetch", error),
      ),
    );
  }

  if (
    homepage && response.ok &&
    response.headers.get("Content-Type")?.includes("text/html")
  ) {
    return refreshIssueCount(context, response);
  }

  return response;
}
