import { assert, assertEquals, assertFalse } from "@std/assert";
import { type Caller, callerOf, Capability } from "../src/mod.ts";

Deno.test("callerOf exposes predicates and a snapshot of all held scopes", () => {
  const prefix = "urn:cap:docs:read:";
  const grant = prefix + "/home";
  const deny = prefix + "-/home/secret";
  const principal = "urn:principal:ada";
  const cap = Capability.scoped([
    grant,
    "urn:cap:principal:" + principal,
    deny,
  ]);
  const caller: Caller = callerOf(cap);

  assert(Object.isFrozen(caller));
  assertFalse(caller.isRoot);
  assertEquals(caller.principal(), principal);
  assert(caller.allows(grant));
  assertFalse(caller.allows(deny));
  assertFalse(caller.allows(prefix + "*"));
  assert(caller.satisfies(prefix + "*"));
  assertEquals(caller.under(prefix), [deny, grant]);
  assertEquals(caller.scopes, cap.scopes);

  (cap.scopes as Set<string>).clear();
  (caller.scopes as Set<string>).clear();
  assertEquals(caller.scopes?.size, 3);
  assertEquals(caller.under(prefix), [deny, grant]);
  assert(caller.allows(grant));
});

Deno.test("callerOf distinguishes root, empty scopes, and ambiguous principals", () => {
  const root = callerOf(Capability.root());
  assert(root.isRoot);
  assertEquals(root.scopes, null);
  assertEquals(root.principal(), null);
  assertEquals(root.under(""), []);
  assert(root.allows("urn:cap:example"));

  const empty = callerOf(Capability.scoped([]));
  assertFalse(empty.isRoot);
  assertEquals(empty.scopes?.size, 0);
  assertFalse(empty.satisfies("*"));

  const ambiguous = callerOf(Capability.scoped([
    "urn:cap:principal:urn:principal:ada",
    "urn:cap:principal:urn:principal:bea",
  ]));
  assertEquals(ambiguous.principal(), null);
});
