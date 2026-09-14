import type {
  AliasScriptDetermination,
  UnicodeRestrictionLevel,
} from "@aaliyah/contracts/v1";

/**
 * Wave 1.3 ALIAS NORMALIZATION AND CONFUSABLE SKELETON — Core's recomputation.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `CanonicalAliasIdentitySchema` in `@aaliyah/contracts/v1` carries a
 * `skeleton` and a `scriptDetermination`, and its own header says both are
 * PRODUCER CLAIMS: the contracts package holds no confusables data and cannot
 * check either. It instructs Core to recompute and to reject disagreement.
 * This module is that recomputation. Nothing here trusts a claim; the caller
 * (`wave1AliasRegistry`) compares Core's output against the claim and refuses
 * the alias when they differ.
 *
 * WHAT THIS SKELETON IS, EXACTLY
 * ------------------------------
 * It is `aaliyah.alias-skeleton/core-subset-v1`. It is NOT a UTS-39 skeleton
 * and this module never claims to be one. A conformant UTS-39 skeleton needs
 * the Unicode `confusables.txt` table (~6600 mappings), which is a dependency
 * this repository is not permitted to add. The contracts value
 * `MEMORY_CONFUSABLE_SKELETON_ALGORITHM` ("uts39-skeleton/unicode-15.1") is a
 * LABEL a producer declares; Core treats it as inert metadata and honours only
 * its own recomputation.
 *
 * COVERED — the skeleton folds all of the following onto one value:
 *   1. NFKC compatibility normalization (Node's built-in ICU, tracking the
 *      Unicode version of the running runtime). This folds fullwidth forms
 *      (ＡＤＭＩＮ), mathematical alphanumerics (𝐚𝐝𝐦𝐢𝐧), ligatures (ﬁ),
 *      superscripts, circled letters and the compatibility ideographs.
 *   2. Full Unicode lowercasing (`String.prototype.toLowerCase`).
 *   3. Removal of invisible and format characters: U+00AD, U+180E, U+200B,
 *      U+200C, U+200D, U+2060, U+FEFF.
 *   4. Removal of nonspacing combining marks (`\p{Mn}`) after NFD, so
 *      "josé" and "jose" fold together. This is DELIBERATELY STRONGER than
 *      UTS-39, which does not strip diacritics wholesale.
 *   5. An EXPLICIT, ENUMERATED homoglyph table (`HOMOGLYPHS` below) mapping
 *      selected Cyrillic, Greek, Armenian and extended-Latin code points onto
 *      their ASCII look-alikes — the class that produced the live alias-hijack
 *      this registry exists to close (Cyrillic U+0430 "а" vs Latin "a").
 *   6. Three alternative full stops used in internationalized hostnames
 *      (U+3002, U+FF61, U+FF0E) folded onto ".".
 *   7. A final NFC normalization, because `CanonicalAliasIdentitySchema`
 *      requires the skeleton to be NFC.
 *
 * NOT COVERED — stated so no reader infers more than is here:
 *   - The complete UTS-39 confusables table. Only the enumerated code points
 *     in `HOMOGLYPHS` are folded. Cyrillic "ԃ", Cherokee "Ꮟ", Coptic, Deseret,
 *     Lisu, Osage and every other look-alike outside the table pass through
 *     unchanged and will NOT collide with their Latin twin on the skeleton
 *     index. Uppercase-only confusable scripts (Cherokee, most of Deseret)
 *     are therefore effectively uncovered.
 *   - UTS-39 WHOLE-SCRIPT confusables (a string entirely in Cyrillic that
 *     reads as Latin) are not detected AS SUCH; they are caught only insofar
 *     as their individual code points appear in `HOMOGLYPHS`.
 *   - Multi-character confusables ("rn" for "m", "vv" for "w", "cl" for "d").
 *     Those are handled ONLY in the look-alike DOMAIN analysis below, not in
 *     the identity skeleton.
 *   - UTS-39 restriction levels `highly_restrictive`,
 *     `moderately_restrictive` and `minimally_restrictive` as Unicode defines
 *     them. `aliasRestrictionLevel` emits only `ascii_only`, `single_script`
 *     and `unrestricted`; computing the intermediate levels requires the
 *     Unicode `IdentifierStatus`/`IdentifierType` data this module does not
 *     carry.
 *   - Bidirectional-text attacks (RLO/LRO reordering). U+202A..U+202E are NOT
 *     stripped; they are non-Common-script-neutral formatting characters and
 *     an alias containing one is left to the script gate.
 *
 * THE DIRECTION OF THE ERROR. Every divergence from UTS-39 above either folds
 * MORE aggressively than UTS-39 (items 2, 3, 4) — producing MORE collisions
 * and therefore MORE refusals — or folds LESS (the uncovered table). The
 * second kind is a real gap: an attacker who finds a homoglyph outside
 * `HOMOGLYPHS` defeats the skeleton index. The mixed-script gate is the second
 * line for exactly that case, and it is why the gate refuses mixed script
 * outright rather than scoring it.
 *
 * THE COST OF OVER-FOLDING, SAID PLAINLY. "josé@x.com" and "jose@x.com" cannot
 * both be bound in one scope. Neither can "admin@x.com" and "ADMIN@x.com"
 * (already true of the normalized alias) nor "ﬁnance@x.com" and
 * "finance@x.com". That is a deliberate availability cost paid for a
 * confusability guarantee, and an operator who does not want it must not use
 * this registry.
 */

/** Core's normalization profile. Not the contracts label; see the header. */
export const CORE_ALIAS_NORMALIZATION_PROFILE =
  "aaliyah.alias-normalization/core-v1" as const;

/** Core's skeleton algorithm. Not UTS-39; see the header. */
export const CORE_ALIAS_SKELETON_ALGORITHM =
  "aaliyah.alias-skeleton/core-subset-v1" as const;

/**
 * Invisible and format characters. An alias containing one of these does not
 * get silently cleaned: `coreNormalizeAlias` removes them, the producer's
 * claimed `normalizedAlias` (which contracts derives WITHOUT this step) then
 * disagrees, and the registry refuses the alias. Removal here exists so that
 * the disagreement is detected, not so that the alias is repaired.
 */
const INVISIBLE = /[\u00ad\u180e\u200b\u200c\u200d\u2060\ufeff]/gu;

/**
 * The enumerated homoglyph table. LOWERCASE SOURCES ONLY, because the skeleton
 * lowercases before it maps; an uppercase entry would be unreachable code that
 * no test could kill.
 *
 * Every entry is a single code point that renders, in common UI fonts, as the
 * ASCII character it maps to. This list is exhaustive of what Core folds — see
 * the "NOT COVERED" section of the header.
 */
const HOMOGLYPHS: ReadonlyMap<string, string> = new Map([
  // --- Cyrillic ---------------------------------------------------------
  ["а", "a"], // а CYRILLIC SMALL LETTER A
  ["в", "b"], // в CYRILLIC SMALL LETTER VE
  ["е", "e"], // е CYRILLIC SMALL LETTER IE
  ["к", "k"], // к CYRILLIC SMALL LETTER KA
  ["м", "m"], // м CYRILLIC SMALL LETTER EM
  ["н", "h"], // н CYRILLIC SMALL LETTER EN
  ["о", "o"], // о CYRILLIC SMALL LETTER O
  ["р", "p"], // р CYRILLIC SMALL LETTER ER
  ["с", "c"], // с CYRILLIC SMALL LETTER ES
  ["т", "t"], // т CYRILLIC SMALL LETTER TE
  ["у", "y"], // у CYRILLIC SMALL LETTER U
  ["х", "x"], // х CYRILLIC SMALL LETTER HA
  ["ѕ", "s"], // ѕ CYRILLIC SMALL LETTER DZE
  ["і", "i"], // і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
  ["ј", "j"], // ј CYRILLIC SMALL LETTER JE
  ["һ", "h"], // һ CYRILLIC SMALL LETTER SHHA
  ["ӏ", "l"], // ӏ CYRILLIC SMALL LETTER PALOCHKA
  ["ԁ", "d"], // ԁ CYRILLIC SMALL LETTER KOMI DE
  ["ԛ", "q"], // ԛ CYRILLIC SMALL LETTER QA
  ["ԝ", "w"], // ԝ CYRILLIC SMALL LETTER WE
  // --- Greek ------------------------------------------------------------
  ["α", "a"], // α GREEK SMALL LETTER ALPHA
  ["ε", "e"], // ε GREEK SMALL LETTER EPSILON
  ["ι", "i"], // ι GREEK SMALL LETTER IOTA
  ["κ", "k"], // κ GREEK SMALL LETTER KAPPA
  ["ν", "v"], // ν GREEK SMALL LETTER NU
  ["ο", "o"], // ο GREEK SMALL LETTER OMICRON
  ["ρ", "p"], // ρ GREEK SMALL LETTER RHO
  ["τ", "t"], // τ GREEK SMALL LETTER TAU
  ["υ", "u"], // υ GREEK SMALL LETTER UPSILON
  ["χ", "x"], // χ GREEK SMALL LETTER CHI
  ["γ", "y"], // γ GREEK SMALL LETTER GAMMA
  ["η", "n"], // η GREEK SMALL LETTER ETA
  ["ϲ", "c"], // ϲ GREEK LUNATE SIGMA SYMBOL
  ["ϳ", "j"], // ϳ GREEK LETTER YOT
  // --- Armenian ---------------------------------------------------------
  ["օ", "o"], // օ ARMENIAN SMALL LETTER OH
  ["ո", "n"], // ո ARMENIAN SMALL LETTER VO
  ["ս", "u"], // ս ARMENIAN SMALL LETTER SEH
  ["գ", "q"], // գ ARMENIAN SMALL LETTER GIM
  // --- Extended Latin and IPA ------------------------------------------
  ["ı", "i"], // ı LATIN SMALL LETTER DOTLESS I
  ["ɑ", "a"], // ɑ LATIN SMALL LETTER ALPHA
  ["ɡ", "g"], // ɡ LATIN SMALL LETTER SCRIPT G
  ["ǀ", "l"], // ǀ LATIN LETTER DENTAL CLICK
  ["ɪ", "i"], // ɪ LATIN LETTER SMALL CAPITAL I
  ["ɩ", "i"], // ɩ LATIN SMALL LETTER IOTA
  // --- Alternative full stops used in hostnames ------------------------
  ["。", "."], // 。 IDEOGRAPHIC FULL STOP
  ["｡", "."], // ｡ HALFWIDTH IDEOGRAPHIC FULL STOP
  ["．", "."], // ． FULLWIDTH FULL STOP (NFKC already folds this)
]);

/**
 * Scripts Core can name. A code point whose script extension set contains none
 * of these makes the determination `undetermined` rather than guessing, which
 * is what `unsupported_codepoint` means on the contracts enum.
 *
 * Ordered: the representative script of a single-script alias is the FIRST
 * entry present in the resolved set, so the answer is deterministic when a
 * code point belongs to several scripts (Han in a Japanese string, say).
 */
const SUPPORTED_SCRIPTS: ReadonlyArray<{ name: string; iso: string }> = [
  { name: "Latin", iso: "Latn" },
  { name: "Cyrillic", iso: "Cyrl" },
  { name: "Greek", iso: "Grek" },
  { name: "Armenian", iso: "Armn" },
  { name: "Hebrew", iso: "Hebr" },
  { name: "Arabic", iso: "Arab" },
  { name: "Devanagari", iso: "Deva" },
  { name: "Thai", iso: "Thai" },
  { name: "Han", iso: "Hani" },
  { name: "Hiragana", iso: "Hira" },
  { name: "Katakana", iso: "Kana" },
  { name: "Hangul", iso: "Hang" },
];

/** Built once. A fresh RegExp per code point would be the hot loop. */
const SCRIPT_MATCHERS: ReadonlyArray<{ iso: string; re: RegExp }> =
  SUPPORTED_SCRIPTS.map((script) => ({
    iso: script.iso,
    re: new RegExp(`\\p{scx=${script.name}}`, "u"),
  }));

/** Script-neutral code points: digits, ".", "@", "-", "_" and friends. */
const SCRIPT_NEUTRAL = /[\p{scx=Common}\p{scx=Inherited}]/u;

/**
 * Core's normalized alias.
 *
 * Contracts computes `observedAlias.normalize("NFC").toLowerCase()` and
 * enforces it. Core computes THE SAME THING AND THEN removes invisible and
 * format characters. The extra step is what makes this comparison a real
 * control rather than a restatement of a check the schema already made: an
 * alias carrying a zero-width joiner parses cleanly against contracts and then
 * disagrees with Core here, and disagreement is a refusal.
 */
export function coreNormalizeAlias(observedAlias: string): string {
  return observedAlias.normalize("NFC").toLowerCase().replace(INVISIBLE, "");
}

/**
 * Core's confusable skeleton. See the module header for exactly what this
 * covers and what it does not.
 */
export function coreAliasSkeleton(value: string): string {
  const folded = value
    .normalize("NFKC")
    .toLowerCase()
    .replace(INVISIBLE, "")
    // NFD then drop nonspacing marks: "é" -> "e". Deliberately stronger than
    // UTS-39; see the header.
    .normalize("NFD")
    .replace(/\p{Mn}/gu, "");
  let mapped = "";
  for (const character of folded) {
    mapped += HOMOGLYPHS.get(character) ?? character;
  }
  // CanonicalAliasIdentitySchema requires an NFC skeleton.
  return mapped.normalize("NFC");
}

/**
 * UTS-39's single-script test, done correctly for the scripts Core supports:
 * a string is single-script when the INTERSECTION of the script-extension sets
 * of its non-neutral code points is non-empty. Script-neutral code points
 * (Common, Inherited) never participate, which is why "admin@x.com" is
 * single-script Latin despite the "@" and the ".".
 */
export function determineAliasScript(value: string): AliasScriptDetermination {
  let intersection: string[] | null = null;
  const union = new Set<string>();
  for (const character of value) {
    if (SCRIPT_NEUTRAL.test(character)) continue;
    const scripts = SCRIPT_MATCHERS.filter((matcher) =>
      matcher.re.test(character),
    ).map((matcher) => matcher.iso);
    if (scripts.length === 0) {
      return { kind: "undetermined", reason: "unsupported_codepoint" };
    }
    for (const iso of scripts) union.add(iso);
    intersection =
      intersection === null
        ? scripts
        : intersection.filter((iso) => scripts.includes(iso));
  }
  if (intersection === null) {
    // Nothing but script-neutral code points. "1234@5678.com" names no script
    // at all, and calling that "single script Latin" would be an invention.
    return { kind: "undetermined", reason: "input_rejected" };
  }
  if (intersection.length === 0) {
    return {
      kind: "mixed_script",
      scripts: SUPPORTED_SCRIPTS.map((script) => script.iso).filter((iso) =>
        union.has(iso),
      ),
    };
  }
  const resolved = intersection;
  const representative = SUPPORTED_SCRIPTS.map((script) => script.iso).find(
    (iso) => resolved.includes(iso),
  );
  // Unreachable: `intersection` is non-empty and every member came from
  // SUPPORTED_SCRIPTS. Fail closed rather than assert.
  if (representative === undefined) {
    return { kind: "undetermined", reason: "unsupported_codepoint" };
  }
  return { kind: "single_script", script: representative };
}

const ASCII_PRINTABLE = /^[\x20-\x7e]*$/u;

/**
 * The restriction level Core is able to justify. Only three of the six
 * contracts values are ever emitted — see "NOT COVERED" in the header.
 */
export function aliasRestrictionLevel(
  value: string,
  determination: AliasScriptDetermination,
): UnicodeRestrictionLevel {
  if (ASCII_PRINTABLE.test(value)) return "ascii_only";
  if (determination.kind === "single_script") return "single_script";
  return "unrestricted";
}

/**
 * The local part and host of an email-shaped alias, or null.
 *
 * Split on the LAST "@": a quoted local part may contain one, a host may not.
 */
export function splitEmailAlias(
  normalizedAlias: string,
): { localPart: string; domain: string } | null {
  const at = normalizedAlias.lastIndexOf("@");
  if (at <= 0 || at === normalizedAlias.length - 1) return null;
  const localPart = normalizedAlias.slice(0, at);
  const domain = normalizedAlias.slice(at + 1);
  if (localPart.includes("@")) return null;
  return { localPart, domain };
}

/**
 * The host part, as Core keys it.
 *
 * HONEST NAMING. The contracts field is called `registrableDomain`, which in
 * the public-suffix sense means eTLD+1. Core does NOT compute eTLD+1: that
 * needs the Public Suffix List, a dependency this repository may not add. Core
 * uses the WHOLE lowercased host. Consequence, so nobody discovers it by
 * surprise: "mail.example.com" and "example.com" are DIFFERENT keys here and
 * do not compare as one registrable domain, and a protected-domain corpus must
 * therefore enumerate the hosts it wants covered.
 *
 * DELIBERATELY UNICODE-AWARE, not ASCII-only. A structural check must answer
 * "is this shaped like a host" and nothing else; "is this host non-ASCII" is
 * the IDN-homograph gate's question, and an ASCII-only pattern here would
 * answer it first and refuse every internationalized host as MALFORMED —
 * hiding the homograph signal behind a shape error and leaving the IDN gate
 * with no reachable input at all.
 */
export const HOST_FORM =
  /^[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)+$/u;

/** True when the host is non-ASCII or already in Punycode A-label form. */
export function isInternationalizedDomain(domain: string): boolean {
  if (!ASCII_PRINTABLE.test(domain)) return true;
  return domain.split(".").some((label) => label.startsWith("xn--"));
}

/**
 * Digit/letter and multi-character substitutions used by typosquatters. This
 * is SEPARATE from the identity skeleton on purpose: folding "1" onto "l"
 * inside the skeleton would collide "user1@x.com" with "userl@x.com" for every
 * tenant, whereas here it only ever raises a RISK SIGNAL against a domain the
 * operator explicitly chose to protect.
 */
function typosquatFold(domain: string): string {
  return domain
    .replace(/0/gu, "o")
    .replace(/1/gu, "l")
    .replace(/3/gu, "e")
    .replace(/4/gu, "a")
    .replace(/5/gu, "s")
    .replace(/7/gu, "t")
    .replace(/8/gu, "b")
    .replace(/\|/gu, "l")
    .replace(/rn/gu, "m")
    .replace(/vv/gu, "w");
}

/** Damerau-Levenshtein distance, capped: anything above 2 answers 3. */
function editDistance(left: string, right: string): number {
  if (Math.abs(left.length - right.length) > 2) return 3;
  const rows = left.length + 1;
  const cols = right.length + 1;
  const grid: number[][] = [];
  for (let row = 0; row < rows; row += 1) {
    grid.push(new Array<number>(cols).fill(0));
  }
  for (let row = 0; row < rows; row += 1) grid[row]![0] = row;
  for (let col = 0; col < cols; col += 1) grid[0]![col] = col;
  for (let row = 1; row < rows; row += 1) {
    for (let col = 1; col < cols; col += 1) {
      const cost = left[row - 1] === right[col - 1] ? 0 : 1;
      let best = Math.min(
        grid[row - 1]![col]! + 1,
        grid[row]![col - 1]! + 1,
        grid[row - 1]![col - 1]! + cost,
      );
      if (
        row > 1 &&
        col > 1 &&
        left[row - 1] === right[col - 2] &&
        left[row - 2] === right[col - 1]
      ) {
        best = Math.min(best, grid[row - 2]![col - 2]! + 1);
      }
      grid[row]![col] = best;
    }
  }
  return grid[rows - 1]![cols - 1]!;
}

export type AliasDomainRisk =
  | "none_detected"
  | "idn_homograph_suspected"
  | "typosquat_suspected"
  | "undetermined";

/**
 * The look-alike risk Core assigns to the host of an email alias, against the
 * protected-domain corpus configured for the alias's scope.
 *
 * ORDER IS THE POLICY:
 *   1. An EXACT match against a protected domain is the LEGITIMATE case and
 *      answers `none_detected`. Without this first, every address at a
 *      protected domain would be refused as a look-alike of itself.
 *   2. A host that is not plain ASCII, or whose skeleton differs from itself,
 *      is `idn_homograph_suspected` — no corpus needed, because the homograph
 *      is visible in the host alone.
 *   3. A host that collapses onto a protected domain under `typosquatFold`,
 *      or that is within one edit of it, is `typosquat_suspected`.
 *   4. Otherwise `none_detected`.
 *
 * WHAT THIS IS NOT. It is not a registrar feed, a reputation service, or a
 * certificate-transparency scan. With an EMPTY corpus, step 3 can never fire,
 * so an unprotected domain is never flagged as a typosquat. That is a
 * deliberate design point — the operator names what is worth protecting — and
 * it is also the limitation: an alias at a look-alike of a domain nobody
 * enumerated is accepted.
 */
export function lookalikeDomainRisk(
  domain: string,
  protectedDomains: readonly string[],
): AliasDomainRisk {
  if (protectedDomains.includes(domain)) return "none_detected";
  // NOTE: a SECOND arm here, `coreAliasSkeleton(domain) !== domain`, would be
  // dead code and was removed rather than kept as an unkillable line. Every
  // code point the skeleton folds is non-ASCII, so any domain it would change
  // has already been answered by the arm above. Adding an ASCII-to-ASCII fold
  // to the skeleton would make such an arm live again, and it would need its
  // own test the day it did.
  if (isInternationalizedDomain(domain)) return "idn_homograph_suspected";
  const candidate = typosquatFold(domain);
  for (const guarded of protectedDomains) {
    if (candidate === typosquatFold(guarded)) return "typosquat_suspected";
    if (editDistance(domain, guarded) <= 1) return "typosquat_suspected";
  }
  return "none_detected";
}
