/**
 * `src/auth.ts` pinned by the shared auth vectors (ledger #1862).
 *
 * `auth_vectors.json` is a VERBATIM copy of ikigai-http's
 * `tests/vectors/auth_vectors.json` at ikigai-http commit 064e474 (PR 46,
 * 0.7.2); do not edit or reformat it here (`deno.json` keeps it out of
 * `deno fmt`, `.gitattributes` keeps it LF): to pick up new vectors, copy the
 * file again. Every case runs. Assertions never print a credential: a failure
 * names the case, not its input.
 */

import { assert, assertEquals } from "@std/assert";
import {
  AuthError,
  base64Decode,
  base64Encode,
  basicAuthorization,
  bearerAuthorization,
  decode_url,
  encode_url,
  parseAuthorization,
} from "../src/auth.ts";

// deno-lint-ignore no-explicit-any
type Case = Record<string, any>;
const vectors = JSON.parse(
  await Deno.readTextFile(new URL("./auth_vectors.json", import.meta.url)),
) as Record<string, Case[] | string | number>;

function cases(section: string): Case[] {
  const c = vectors[section];
  if (!Array.isArray(c) || c.length === 0) {
    throw new Error(`section ${section} missing or empty`);
  }
  return c;
}

function refusal(c: Case, f: () => unknown) {
  try {
    f();
  } catch (e) {
    assert(e instanceof AuthError, c.name);
    assertEquals(e.code, c.error, c.name);
    return;
  }
  throw new Error(`${c.name}: not refused`);
}

function fromHex(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
}

Deno.test("auth vectors: no unknown sections", () => {
  assertEquals(Object.keys(vectors).sort(), [
    "about",
    "base64",
    "base64_refusals",
    "base64_url",
    "base64_url_refusals",
    "basic",
    "basic_refusals",
    "bearer",
    "bearer_refusals",
    "scheme",
    "version",
  ]);
});

Deno.test("auth vectors: basic", () => {
  for (const c of cases("basic")) {
    assert(basicAuthorization(c.user, c.password) === c.expect, c.name);
  }
});

Deno.test("auth vectors: basic refusals", () => {
  for (const c of cases("basic_refusals")) {
    refusal(c, () => basicAuthorization(c.user, c.password));
  }
});

Deno.test("auth vectors: bearer", () => {
  for (const c of cases("bearer")) {
    assert(bearerAuthorization(c.token) === c.expect, c.name);
  }
});

Deno.test("auth vectors: bearer refusals", () => {
  for (const c of cases("bearer_refusals")) {
    refusal(c, () => bearerAuthorization(c.token));
  }
});

Deno.test("auth vectors: scheme", () => {
  for (const c of cases("scheme")) {
    assertEquals(parseAuthorization(c.value), c.expect, c.name);
  }
});

Deno.test("auth vectors: base64 encodes and decodes", () => {
  for (const c of cases("base64")) {
    const bytes = c.hex !== undefined
      ? fromHex(c.hex)
      : new TextEncoder().encode(c.text);
    assertEquals(base64Encode(bytes), c.encoded, c.name);
    assertEquals(base64Decode(c.encoded), bytes, c.name);
  }
});

Deno.test("auth vectors: base64 refusals", () => {
  for (const c of cases("base64_refusals")) {
    refusal(c, () => base64Decode(c.encoded));
  }
});

Deno.test("an AuthError never carries the credential", () => {
  for (
    const f of [
      () => basicAuthorization("us:er", "hunter2-secret"),
      () => basicAuthorization("user", "hunter2\n-secret"),
      () => bearerAuthorization("hunter2 secret"),
      () => base64Decode("hunter2-secret"),
      () => decode_url("hunter2-secret!!"),
    ]
  ) {
    try {
      f();
    } catch (e) {
      assert(!String(e).includes("hunter2"));
      assert(!JSON.stringify(e).includes("hunter2"));
      continue;
    }
    throw new Error("not refused");
  }
});

Deno.test("auth vectors: base64url encodes and decodes", () => {
  for (const c of cases("base64_url")) {
    const bytes = c.hex !== undefined
      ? fromHex(c.hex)
      : new TextEncoder().encode(c.text);
    assert(encode_url(bytes) === c.encoded, c.name);
    const decoded = decode_url(c.encoded);
    assert(
      decoded.length === bytes.length &&
        decoded.every((b, i) => b === bytes[i]),
      c.name,
    );
  }
});

Deno.test("auth vectors: base64url refusals", () => {
  for (const c of cases("base64_url_refusals")) {
    refusal(c, () => decode_url(c.encoded));
  }
});

Deno.test("base64url errors explain the rule without input", () => {
  const reasons = [
    [
      "c2VjcmV0!!",
      "a character outside the URL-safe alphabet, or misplaced padding",
    ],
    ["AAAAA", "a length that no unpadded encoding has"],
    ["Zh", "nonzero unused bits in the last symbol (RFC 4648 §3.5)"],
    ["Zg==", "padding is not allowed"],
  ];
  for (const [input, reason] of reasons) {
    try {
      decode_url(input);
    } catch (e) {
      assert(e instanceof AuthError);
      assert(!String(e).includes(input));
      assert(!JSON.stringify(e).includes(input));
      assert(!String(e).includes("!"));
      assertEquals(
        e.message,
        "base64-invalid: " +
          "not canonical base64url (RFC 4648 §5, URL-safe alphabet, unpadded): " +
          reason,
      );
      continue;
    }
    throw new Error("not refused");
  }
});
