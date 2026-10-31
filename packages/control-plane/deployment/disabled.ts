// SPDX-License-Identifier: AGPL-3.0-or-later
/** Safe candidate deployment entry: no DO bindings, effects or activation. */
export default {
  fetch() {
    return Response.json(
      { reason: "production_deployment_disabled", activation_permitted: false },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  },
};
