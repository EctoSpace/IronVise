/** The shell command that creates this installation's issuer key.
 *
 * The History export shows this when a certificate is unsigned. A Unix
 * `VAR=value command` assignment is not a command on Windows: cmd.exe
 * ignores it and PowerShell treats it as a syntax error. A path with a
 * drive letter or a backslash is a Windows path.
 */
export function issuerKeyCommand(dir: string): string {
  const windows = /^[A-Za-z]:[\\/]/.test(dir) || dir.includes("\\");
  if (windows) {
    return `set "ECTO_DATA_DIR=${dir}" && ironvise issuer-key init`;
  }
  return `ECTO_DATA_DIR="${dir}" ironvise issuer-key init`;
}
