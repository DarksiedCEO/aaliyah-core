import type {
  CommunicationStyle,
  StyleCta,
  StyleFormality,
  StyleLength,
} from "@aaliyah/contracts/v1";

export type StyleFields = {
  tone: string;
  lengthPreference: StyleLength;
  formality: StyleFormality;
  ctaBehavior: StyleCta;
  greeting: string;
  signoff: string;
  forbiddenPhrases: string[];
};

/**
 * Built-in default style fields per style id. `professional` is the safe
 * default used as the deterministic fallback when no profile is stored.
 */
const DEFAULTS: Record<CommunicationStyle, StyleFields> = {
  professional: {
    tone: "professional and courteous",
    lengthPreference: "medium",
    formality: "formal",
    ctaBehavior: "soft",
    greeting: "Hi",
    signoff: "Best regards",
    forbiddenPhrases: [],
  },
  friendly: {
    tone: "warm and approachable",
    lengthPreference: "medium",
    formality: "casual",
    ctaBehavior: "soft",
    greeting: "Hey",
    signoff: "Cheers",
    forbiddenPhrases: [],
  },
  direct: {
    tone: "direct and succinct",
    lengthPreference: "short",
    formality: "neutral",
    ctaBehavior: "direct",
    greeting: "Hi",
    signoff: "Thanks",
    forbiddenPhrases: [],
  },
  executive: {
    tone: "confident and executive",
    lengthPreference: "short",
    formality: "formal",
    ctaBehavior: "direct",
    greeting: "Hi",
    signoff: "Best",
    forbiddenPhrases: [],
  },
  concise: {
    tone: "concise and to the point",
    lengthPreference: "short",
    formality: "neutral",
    ctaBehavior: "soft",
    greeting: "Hi",
    signoff: "Best",
    forbiddenPhrases: [],
  },
  // `custom` falls back to professional fields until the user supplies notes.
  custom: {
    tone: "professional and courteous",
    lengthPreference: "medium",
    formality: "formal",
    ctaBehavior: "soft",
    greeting: "Hi",
    signoff: "Best regards",
    forbiddenPhrases: [],
  },
};

export const SAFE_DEFAULT_STYLE: CommunicationStyle = "professional";

export function defaultStyleFields(styleId: CommunicationStyle): StyleFields {
  return { ...DEFAULTS[styleId], forbiddenPhrases: [...DEFAULTS[styleId].forbiddenPhrases] };
}
