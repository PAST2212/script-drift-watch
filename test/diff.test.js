import { test } from "node:test";
import assert from "node:assert/strict";
import { scriptKey, scriptHost, diffSite } from "../src/diff.js";

// ---- Open review point: blob: scripts get a new random UUID on every page load ----
test("a blob: script is identified by its origin and content hash, not by its random UUID", () => {
  const hash = "abcdef0123456789aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.equal(scriptKey("blob:https://shop.example/59c8bd86-2dac-4934-b8f8-24237c3be12a", hash), "blob:https://shop.example/sha256-abcdef0123456789");
  assert.equal(scriptKey("blob:https://shop.example/12935221-b2f1-4028-917c-a484f2ce4142", hash), "blob:https://shop.example/sha256-abcdef0123456789");
});

test("the host of a blob: script is the host of the page origin that created it", () => {
  assert.equal(scriptHost("blob:https://shop.example/59c8bd86-2dac-4934-b8f8-24237c3be12a"), "shop.example");
  assert.equal(scriptHost("blob:https://shop.example/sha256-abcdef0123456789"), "shop.example");
  assert.equal(scriptHost("https://cdn.vendor.example:8443/a.js?v=1"), "cdn.vendor.example:8443");
});

test("scriptKey drops query string and fragment so cache-busters keep the same identity", () => {
  assert.equal(
    scriptKey("https://cdn.optimizely.com/js/123.js?v=42#x"),
    scriptKey("https://cdn.optimizely.com/js/123.js?v=43"),
  );
  assert.equal(scriptKey("https://cdn.optimizely.com/js/123.js?v=42"), "https://cdn.optimizely.com/js/123.js");
});

test("diffSite reports added, changed and removed scripts", () => {
  const baseline = {
    "https://a.example/a.js": { hash: "h1", url: "https://a.example/a.js" },
    "https://b.example/b.js": { hash: "h2", url: "https://b.example/b.js" },
    "https://c.example/c.js": { hash: "h3", url: "https://c.example/c.js" },
  };
  const current = {
    "https://a.example/a.js": { hash: "h1", url: "https://a.example/a.js" },
    "https://b.example/b.js": { hash: "CHANGED", url: "https://b.example/b.js?v=2" },
    "https://d.example/d.js": { hash: "h4", url: "https://d.example/d.js" },
  };
  assert.deepEqual(diffSite(baseline, current), {
    added: ["https://d.example/d.js"],
    changed: ["https://b.example/b.js"],
    removed: ["https://c.example/c.js"],
  });
});

test("diffSite with an empty baseline reports everything as added", () => {
  const current = { "https://a.example/a.js": { hash: "h1", url: "https://a.example/a.js" } };
  assert.deepEqual(diffSite({}, current), { added: ["https://a.example/a.js"], changed: [], removed: [] });
});

test("diffSite treats a missing baseline (undefined) like an empty one", () => {
  assert.deepEqual(diffSite(undefined, {}), { added: [], changed: [], removed: [] });
});

// Final review I4: only cache-buster parameters may be dropped from the identity.
test("scriptKey keeps identifying query parameters apart (gtag ?id=G-AAA vs ?id=AW-BBB)", () => {
  assert.notEqual(
    scriptKey("https://www.googletagmanager.com/gtag/js?id=G-AAA"),
    scriptKey("https://www.googletagmanager.com/gtag/js?id=AW-BBB"),
  );
});

test("scriptKey drops common cache-buster parameters but keeps the rest, order-independent", () => {
  assert.equal(
    scriptKey("https://x.example/a.js?id=1&_=1700000000&cb=9&lang=de"),
    scriptKey("https://x.example/a.js?lang=de&id=1&t=5"),
  );
  assert.equal(scriptKey("https://x.example/a.js?lang=de&id=1&t=5"), "https://x.example/a.js?id=1&lang=de");
});
test("a changed secondary response body is visible when a normalized script key has several editions", () => {
  const key = "https://cdn.example/experiment.js";
  const before = { [key]: { url: key, hash: "a", hashes: ["a", "b"] } };
  const after = { [key]: { url: key, hash: "a", hashes: ["a", "c"] } };
  assert.deepEqual(diffSite(before, after).changed, [key]);
  assert.deepEqual(diffSite(after, after).changed, []);
  assert.deepEqual(diffSite(after, { [key]: { url: key, hash: "a" } }).changed, [key]);
});
