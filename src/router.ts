import type { JevJudgment, RouteOutcome, RouterConfig } from "./contracts.js";
import type { EvidencePacket } from "./packets.js";

const keys = ["contextMin", "safeRiskMax", "highRiskMin", "pathMin", "controlEffectiveMin", "controlAbsentMax", "impactMin", "directExploitabilityMin"] as const;

export function parseRouterConfig(value: unknown): RouterConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("router config must be an object");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).length !== keys.length || keys.some((key) => !(key in input))) throw new Error("router config keys are invalid");
  for (const key of keys) {
    const maximum = key === "directExploitabilityMin" ? 3 : 1;
    if (typeof input[key] !== "number" || !Number.isFinite(input[key]) || input[key] < 0 || input[key] > maximum) throw new Error(`router config ${key} must be a finite number in range`);
  }
  if ((input.safeRiskMax as number) > (input.highRiskMin as number) || (input.controlAbsentMax as number) > (input.controlEffectiveMin as number)) throw new Error("router config thresholds overlap");
  return Object.freeze(Object.fromEntries(keys.map((key) => [key, input[key]])) as unknown as RouterConfig);
}

export function route(packet: EvidencePacket, judgment: JevJudgment, config: RouterConfig): RouteOutcome {
  if (Object.values(packet.contextResolution).some((status) => status === "unresolved")) return "insufficient_context";
  if (judgment.kind === "abstain") return "needs_deep_review";
  const { answers } = judgment;
  if (answers.enough_context.noul < config.contextMin) return "insufficient_context";
  const families = [["injection", answers.is_injection.noul], ["broken_access_control", answers.is_broken_access_control.noul], ["ssrf", answers.is_ssrf.noul]] as const;
  const risk = Math.max(...families.map(([, value]) => value));
  const family = families.filter(([, value]) => value === risk);
  if (family.length !== 1) return "needs_deep_review";
  const [name] = family[0]!;
  const pathSupport = name === "broken_access_control" ? answers.crosses_authorization_boundary.noul : Math.min(answers.untrusted_influence.noul, answers.reaches_sensitive_operation.noul);
  const control = name === "broken_access_control" ? answers.authorization_enforced.noul : answers.validation_blocks_attack.noul;
  if (risk >= config.highRiskMin && pathSupport >= config.pathMin && answers.security_impact.noul >= config.impactMin && control <= config.controlAbsentMax && answers.exploitability.score >= config.directExploitabilityMin) return "likely_vulnerability";
  if (risk <= config.safeRiskMax && answers.exploitability.score < config.directExploitabilityMin && (pathSupport <= config.safeRiskMax || control >= config.controlEffectiveMin)) return "likely_safe";
  return "needs_deep_review";
}
