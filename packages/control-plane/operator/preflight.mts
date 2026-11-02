// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { sourcePreflight } from "../src/source-preflight.ts";
const args = process.argv.slice(2);
if (
  ![2, 3].includes(args.length) ||
  args[0] !== "--source-db" ||
  !args[1] ||
  (args.length === 3 && args[2] !== "--retain-local-history")
)
  throw Error("explicit_source_db_required: read-only aggregate metadata; no snapshot export");
const db = new DatabaseSync(args[1], { readOnly: true });
try {
  db.exec("BEGIN");
  const result = sourcePreflight(db, args[2] ? "local_archive" : "include");
  db.exec("ROLLBACK");
  console.log(JSON.stringify({ ...result, consistency: "single_read_transaction" }));
  if (!result.fits_current_materialized_path) process.exitCode = 2;
} finally {
  db.close();
}
