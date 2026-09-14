import assert from "node:assert/strict";
import test from "node:test";

import {
  CORE_ALIAS_NORMALIZATION_PROFILE,
  CORE_ALIAS_SKELETON_ALGORITHM,
  HOST_FORM,
  aliasRestrictionLevel,
  coreAliasSkeleton,
  coreNormalizeAlias,
  determineAliasScript,
  isInternationalizedDomain,
  lookalikeDomainRisk,
  splitEmailAlias,
} from "../src/application/memory/wave1AliasSkeleton";

/**
 * The skeleton, pinned by HARD-CODED EXPECTATIONS.
 *
 * This matters more than it looks. The integration tests compute their fixture
 * skeletons with the SAME function they are testing, so deleting a homoglyph
 * mapping moves both sides of those comparisons equally and several of them
 * stay green. The literals below are the control that cannot move: remove
 * `["а", "a"]` from the table and `"аdmin@x.com"` stops folding onto
 * `"admin@x.com"` right here.
 *
 * These are UNIT tests. They prove what one function computes. They prove
 * nothing about uniqueness, storage or concurrency — that is
 * `tests/wave1AliasRegistryPostgres.integration.test.ts`, against a real
 * database.
 */

test("the algorithm labels are Core's own, and are not UTS-39", () => {
  assert.equal(
    CORE_ALIAS_SKELETON_ALGORITHM,
    "aaliyah.alias-skeleton/core-subset-v1",
  );
  assert.equal(
    CORE_ALIAS_NORMALIZATION_PROFILE,
    "aaliyah.alias-normalization/core-v1",
  );
  assert.ok(
    !CORE_ALIAS_SKELETON_ALGORITHM.includes("uts39"),
    "Core must not label its subset as a UTS-39 skeleton",
  );
});

test("Cyrillic homoglyphs fold onto their Latin look-alikes", () => {
  // U+0430 CYRILLIC SMALL LETTER A.
  assert.equal(coreAliasSkeleton("аdmin@x.com"), "admin@x.com");
  // Whole-script Cyrillic: с е о / х / с о м.
  assert.equal(
    coreAliasSkeleton("сео@х.сом"),
    "ceo@x.com",
  );
  assert.equal(coreAliasSkeleton("рayрal@x.com"), "paypal@x.com");
});

test("Greek and Armenian homoglyphs fold onto their Latin look-alikes", () => {
  // U+03BF GREEK SMALL LETTER OMICRON, U+03B1 ALPHA.
  assert.equal(coreAliasSkeleton("οαk@x.com"), "oak@x.com");
  // U+0585 ARMENIAN SMALL LETTER OH.
  assert.equal(coreAliasSkeleton("օps@x.com"), "ops@x.com");
});

test("NFKC folds fullwidth, ligature and mathematical alphanumeric forms", () => {
  assert.equal(coreAliasSkeleton("ｊose@corp.example"), "jose@corp.example");
  assert.equal(coreAliasSkeleton("ﬁnance@x.com"), "finance@x.com");
  assert.equal(coreAliasSkeleton("\u{1D41A}dmin@x.com"), "admin@x.com");
});

test("combining marks are stripped, which is stronger than UTS-39 and is a cost", () => {
  assert.equal(coreAliasSkeleton("josé@corp.example"), "jose@corp.example");
  // Decomposed and precomposed reach the same skeleton.
  assert.equal(coreAliasSkeleton("josé@corp.example"), "jose@corp.example");
  // The documented availability cost: these two cannot coexist in one scope.
  assert.equal(
    coreAliasSkeleton("josé@corp.example"),
    coreAliasSkeleton("jose@corp.example"),
  );
});

test("a plain ASCII alias is its own skeleton", () => {
  assert.equal(coreAliasSkeleton("ceo@example.com"), "ceo@example.com");
  assert.equal(coreAliasSkeleton("ceo@examp1e.com"), "ceo@examp1e.com");
});

test("the skeleton is NFC, as CanonicalAliasIdentitySchema requires", () => {
  for (const value of [
    "josé@corp.example",
    "аdmin@x.com",
    "ﬁnance@x.com",
  ]) {
    const skeleton = coreAliasSkeleton(value);
    assert.equal(skeleton, skeleton.normalize("NFC"));
  }
});

test("an uncovered homoglyph passes through, and the header says so", () => {
  // U+0501 is IN the table; U+0503 (CYRILLIC SMALL LETTER KOMI DJE) is not.
  assert.equal(coreAliasSkeleton("ԁe@x.com"), "de@x.com");
  assert.notEqual(coreAliasSkeleton("ԃe@x.com"), "de@x.com");
});

test("normalization removes invisible characters so the producer's claim disagrees", () => {
  const zeroWidth = "ad​min@x.com";
  // What contracts derives, and therefore what a producer must claim.
  assert.equal(zeroWidth.normalize("NFC").toLowerCase(), zeroWidth);
  // What Core derives.
  assert.equal(coreNormalizeAlias(zeroWidth), "admin@x.com");
  assert.notEqual(coreNormalizeAlias(zeroWidth), zeroWidth);
  assert.equal(coreNormalizeAlias("CEO@Example.COM"), "ceo@example.com");
  assert.equal(coreNormalizeAlias("ad­min@x.com"), "admin@x.com");
});

test("script determination is the intersection of script-extension sets", () => {
  assert.deepEqual(determineAliasScript("ceo@example.com"), {
    kind: "single_script",
    script: "Latn",
  });
  // Script-neutral code points never make a string mixed.
  assert.deepEqual(determineAliasScript("a1b2@x-y.com"), {
    kind: "single_script",
    script: "Latn",
  });
  assert.deepEqual(
    determineAliasScript("сео@х.сом"),
    { kind: "single_script", script: "Cyrl" },
  );
});

test("one Cyrillic code point among Latin ones is mixed script", () => {
  const determination = determineAliasScript("аdmin@x.com");
  assert.equal(determination.kind, "mixed_script");
  assert.ok(determination.kind === "mixed_script");
  assert.deepEqual(determination.scripts, ["Latn", "Cyrl"]);
});

test("a script Core does not support is undetermined, never guessed", () => {
  // U+1200 ETHIOPIC SYLLABLE HA is outside SUPPORTED_SCRIPTS.
  assert.deepEqual(determineAliasScript("ሀdmin@x.com"), {
    kind: "undetermined",
    reason: "unsupported_codepoint",
  });
  // Nothing but script-neutral code points names no script at all.
  assert.deepEqual(determineAliasScript("1234@5678.com".replace(/[a-z]/gu, "1")), {
    kind: "undetermined",
    reason: "input_rejected",
  });
});

test("only the three restriction levels Core can justify are ever emitted", () => {
  const ascii = determineAliasScript("ceo@example.com");
  assert.equal(aliasRestrictionLevel("ceo@example.com", ascii), "ascii_only");
  const accented = determineAliasScript("josé@corp.example");
  assert.equal(
    aliasRestrictionLevel("josé@corp.example", accented),
    "single_script",
  );
  const mixed = determineAliasScript("аdmin@x.com");
  assert.equal(aliasRestrictionLevel("аdmin@x.com", mixed), "unrestricted");
});

test("an email alias splits on the last @ and the host must be well formed", () => {
  assert.deepEqual(splitEmailAlias("ceo@example.com"), {
    localPart: "ceo",
    domain: "example.com",
  });
  assert.equal(splitEmailAlias("no-at-sign.example"), null);
  assert.equal(splitEmailAlias("@example.com"), null);
  assert.equal(splitEmailAlias("ceo@"), null);
  assert.equal(HOST_FORM.test("example.com"), true);
  assert.equal(HOST_FORM.test("localhost"), false);
  assert.equal(HOST_FORM.test("-bad.example.com"), false);
  // The shape check is Unicode-aware ON PURPOSE. Refusing an internationalized
  // host HERE would answer "malformed" for every IDN homograph and leave the
  // homograph gate with no reachable input; deciding non-ASCII is that gate's
  // job, and it is exercised right below.
  assert.equal(HOST_FORM.test("х.сом"), true);
  assert.equal(lookalikeDomainRisk("х.сом", []), "idn_homograph_suspected");
});

test("a digit-substituted host is a typosquat of a protected domain", () => {
  assert.equal(
    lookalikeDomainRisk("examp1e.com", ["example.com"]),
    "typosquat_suspected",
  );
  assert.equal(
    lookalikeDomainRisk("examp!e.com".replace("!", "l"), ["example.com"]),
    "none_detected",
  );
  // One edit away also counts.
  assert.equal(
    lookalikeDomainRisk("exemple.com", ["example.com"]),
    "typosquat_suspected",
  );
  // "rn" for "m".
  assert.equal(
    lookalikeDomainRisk("exarnple.com", ["example.com"]),
    "typosquat_suspected",
  );
  // TWO substitutions: too far for the edit-distance arm, caught only by the
  // digit fold. This is what makes the two arms separable controls.
  assert.equal(
    lookalikeDomainRisk("3xamp13.com", ["example.com"]),
    "typosquat_suspected",
  );
  // And one that neither arm reaches, so "typosquat" is not simply the answer.
  assert.equal(
    lookalikeDomainRisk("completely-different.test", ["example.com"]),
    "none_detected",
  );
});

test("the protected domain itself is the legitimate case, not a look-alike", () => {
  assert.equal(lookalikeDomainRisk("example.com", ["example.com"]), "none_detected");
  assert.equal(lookalikeDomainRisk("unrelated.test", ["example.com"]), "none_detected");
});

test("a non-ASCII or punycode host is an IDN homograph suspect with no corpus at all", () => {
  assert.equal(
    lookalikeDomainRisk("х.сом", []),
    "idn_homograph_suspected",
  );
  assert.equal(lookalikeDomainRisk("xn--80ak6aa92e.com", []), "idn_homograph_suspected");
  assert.equal(isInternationalizedDomain("example.com"), false);
  assert.equal(isInternationalizedDomain("xn--80ak6aa92e.com"), true);
});

test("an EMPTY corpus cannot raise a typosquat signal, which is the stated limit", () => {
  assert.equal(lookalikeDomainRisk("examp1e.com", []), "none_detected");
});
