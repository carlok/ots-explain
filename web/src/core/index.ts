export * from "./bytes.js";
export * from "./hashes.js";
export * from "./tx.js";
export * from "./parse.js";
export * from "./phases.js";
export * from "./ledger.js";
export * from "./report.js";
export * from "./canonical.js";
export * from "./permalink.js";
export * from "./stamp.js";

import type { BlobLike } from "./hashes.js";
import type { FileInput } from "./report.js";
import { hashBlob } from "./hashes.js";

/** Wrap a Blob/File as the `file` option of buildReport (hashed lazily, in 4 MiB chunks). */
export function fileFromBlob(blob: BlobLike, onProgress?: (done: number, total: number) => void): FileInput {
  return { size: blob.size, digest: (alg) => hashBlob(blob, alg, onProgress) };
}
