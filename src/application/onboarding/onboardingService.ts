import {
  OnboardingStateSchema,
  DEFAULT_OPERATING_MODE,
  DEFAULT_COMMUNICATION_STYLE,
  type CommunicationStyle,
  type DraftOpportunity,
  type OnboardingState,
  type OnboardingStep,
  type OperatingMode,
  type UseCase,
  type WorkspacePreferences,
} from "@aaliyah/contracts/v1";

import { requireTenantContext } from "../../governance/requireTenantContext";
import { savePreferences } from "./preferencesStore";

export type OnboardingAction =
  | { type: "begin" }
  | { type: "set_use_case"; useCase: UseCase }
  | { type: "connect_gmail"; connected: boolean }
  | { type: "set_mode"; mode: OperatingMode }
  | { type: "set_style"; style: CommunicationStyle }
  | { type: "run_discovery"; opportunities: DraftOpportunity[] }
  | { type: "accept_opportunities" };

const NEXT_STEP: Record<OnboardingStep, OnboardingStep> = {
  welcome: "choose_use_case",
  choose_use_case: "connect_gmail",
  connect_gmail: "choose_mode",
  choose_mode: "choose_style",
  choose_style: "inbox_discovery",
  inbox_discovery: "first_opportunities",
  first_opportunities: "complete",
  complete: "complete",
};

function expect(state: OnboardingState, step: OnboardingStep): void {
  if (state.step !== step) {
    throw new Error(
      `Onboarding action invalid at step "${state.step}" (expected "${step}")`,
    );
  }
}

export function startOnboarding(input: {
  tenantId: string;
  userId: string;
  workspaceId?: string;
  now?: () => string;
}): OnboardingState {
  const tenant = requireTenantContext({
    tenantId: input.tenantId,
    userId: input.userId,
    workspaceId: input.workspaceId,
  });
  const now = input.now ?? (() => new Date().toISOString());

  return OnboardingStateSchema.parse({
    tenantId: tenant.tenantId,
    workspaceId: tenant.workspaceId,
    userId: tenant.userId,
    step: "welcome",
    gmailConnected: false,
    opportunities: [],
    startedAt: now(),
  });
}

/**
 * Advance the onboarding state machine. Each action is only valid at its step,
 * so the minimum flow (welcome → use case → gmail → mode → style → discovery →
 * first opportunities → complete) is enforced. On completion, durable
 * per-(tenant, workspace, user) preferences are written — always with
 * `autoSend: false`. Defaults: mode `draft_replies`, style `professional`.
 */
export function advanceOnboarding(
  state: OnboardingState,
  action: OnboardingAction,
  options?: { now?: () => string },
): OnboardingState {
  const now = options?.now ?? (() => new Date().toISOString());

  switch (action.type) {
    case "begin":
      expect(state, "welcome");
      return { ...state, step: NEXT_STEP.welcome };

    case "set_use_case":
      expect(state, "choose_use_case");
      return { ...state, useCase: action.useCase, step: NEXT_STEP.choose_use_case };

    case "connect_gmail":
      expect(state, "connect_gmail");
      if (!action.connected) {
        throw new Error("Gmail connection is required to continue onboarding");
      }
      return { ...state, gmailConnected: true, step: NEXT_STEP.connect_gmail };

    case "set_mode":
      expect(state, "choose_mode");
      return { ...state, operatingMode: action.mode, step: NEXT_STEP.choose_mode };

    case "set_style":
      expect(state, "choose_style");
      return {
        ...state,
        communicationStyle: action.style,
        step: NEXT_STEP.choose_style,
      };

    case "run_discovery":
      expect(state, "inbox_discovery");
      return {
        ...state,
        opportunities: action.opportunities.slice(0, 3),
        step: NEXT_STEP.inbox_discovery,
      };

    case "accept_opportunities": {
      expect(state, "first_opportunities");
      const prefs: WorkspacePreferences = {
        tenantId: state.tenantId,
        workspaceId: state.workspaceId,
        userId: state.userId,
        useCase: state.useCase ?? "inbox_management",
        operatingMode: state.operatingMode ?? DEFAULT_OPERATING_MODE,
        communicationStyle: state.communicationStyle ?? DEFAULT_COMMUNICATION_STYLE,
        gmailConnected: state.gmailConnected,
        autoSend: false,
      };
      savePreferences(prefs);
      return { ...state, step: "complete", completedAt: now() };
    }

    default: {
      const _exhaustive: never = action;
      throw new Error(`Unknown onboarding action: ${JSON.stringify(_exhaustive)}`);
    }
  }
}
