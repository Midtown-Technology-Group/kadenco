// SPDX-License-Identifier: AGPL-3.0-or-later
// null is the MCP Events explicit nonexpiring lifetime, not an access grant.
// Missing/malformed lifetimes fail closed. Authorization is checked separately.
export const subscriptionActive = (s, now) =>
  s?.active === true &&
  ((s.expires === null && s.nonExpiring === true) ||
    (typeof s.expires === "number" && Number.isFinite(s.expires) && s.expires > now));
export const subscriptionState = (s, now) =>
  !s?.active ? "inactive" : subscriptionActive(s, now) ? "active" : "expired";
export const subscriptionExpiry = (s) =>
  s.expires === null ? null : new Date(s.expires).toISOString();
