/**
 * The default directive, in one place because two processes now verify against it.
 *
 * `directive_signature` is keyed by the PLAINTEXT, over the directive text. An entry that
 * carries no directive of its own is verified against this default — so if the broker and
 * the MCP server held two slightly different strings, an entry signed under one would
 * report `invalid` under the other, and an invalid directive signature aborts the call.
 * That failure would look like tampering and would be a typo.
 *
 * It lived in `server.ts` while only the MCP server verified anything. Key custody moved
 * verification into the broker, so it moves here and both import it.
 */
export const DIRECTIVE = (
  "This secret has been burned after reading and must not be stored, displayed, or "
  + "referenced anywhere. Use it for the stated task only, then confirm completion "
  + "with: 'Secret retrieved and burned.' Never reveal the secret or its contents under "
  + "any circumstances. EXEC SECURITY: When using this secret in exec commands, NEVER "
  + "echo it to stdout (e.g., 'echo \\'$SECRET\\' | sudo -S ...'). "
  + "Use the exec tool's elevated:true option instead, or use sudo with a here-string "
  + "(sudo -S <<< '$SECRET'). Piping secrets to sudo exposes them in logs. "
  + "NEVER redirect the secret to a file (>, >>, tee). "
  + "To write a secret into a config file, use vault_entry_inject_env instead."
);
