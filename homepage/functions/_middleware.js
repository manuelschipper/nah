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

export async function onRequest(context) {
  const response = await context.next();
  const platform = INSTALLERS.get(new URL(context.request.url).pathname);

  if (context.request.method === "GET" && response.ok && platform) {
    const day = new Date().toISOString().slice(0, 10);
    context.waitUntil(
      recordInstallerFetch(context.env.INSTALL_METRICS, day, platform).catch(
        (error) => console.error("failed to record installer fetch", error),
      ),
    );
  }

  return response;
}
