import { describe, expect, it } from "vitest";
import { issuerKeyCommand } from "./issuerHint";

describe("issuerKeyCommand", () => {
  it("uses a Unix assignment for a POSIX data directory", () => {
    expect(
      issuerKeyCommand("/Users/me/Library/Application Support/io.ectoledger.agent-ledger"),
    ).toBe(
      'ECTO_DATA_DIR="/Users/me/Library/Application Support/io.ectoledger.agent-ledger" ironvise issuer-key init',
    );
  });

  it("uses cmd.exe syntax for a Windows data directory", () => {
    expect(
      issuerKeyCommand("C:\\Users\\me\\AppData\\Roaming\\io.ectoledger.agent-ledger"),
    ).toBe(
      'set "ECTO_DATA_DIR=C:\\Users\\me\\AppData\\Roaming\\io.ectoledger.agent-ledger" && ironvise issuer-key init',
    );
  });
});
