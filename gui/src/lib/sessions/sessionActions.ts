// IPC call wrappers for History's per-session actions (verify, export), kept
// apart from the view so `Sessions.svelte` only orchestrates state.

import { invoke } from "@tauri-apps/api/core";
import { appDataDir } from "@tauri-apps/api/path";
import { issuerKeyCommand } from "../issuerHint";
import type { VerifyResponse } from "../verification";

export function verifySessionChain(sessionId: string): Promise<VerifyResponse> {
  return invoke<VerifyResponse>("verify_session_chain", { sessionId });
}

export function exportCertificateBytes(sessionId: string): Promise<number[]> {
  return invoke<number[]>("export_certificate", { sessionId });
}

export function downloadReportBytes(sessionId: string): Promise<number[]> {
  return invoke<number[]>("download_report", { sessionId });
}

/** Say how the exported certificate is signed. An audit run rotates its
 *  key, so the app does not keep it, and its certificate is unsigned unless
 *  this installation has an issuer key; saying nothing let an unsigned file
 *  pass for a signed one until `verify-cert --strict` refused it. */
export async function signatureNote(bytes: number[]): Promise<string> {
  let cert: { signature?: unknown; issuer?: unknown };
  try {
    cert = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes)));
  } catch {
    return "";
  }
  if (cert.signature) return "Signed with the session's key.";
  if (cert.issuer) return "Countersigned by this installation's issuer key.";
  let dir = "<the app's data folder>";
  try {
    dir = await appDataDir();
  } catch {
    /* keep the placeholder */
  }
  return (
    "It is unsigned: anyone can check its contents, but nothing in it says who issued it, " +
    "and verify-cert --strict refuses it. To have exports countersigned, create this " +
    `installation's issuer key once: ${issuerKeyCommand(dir)}`
  );
}
