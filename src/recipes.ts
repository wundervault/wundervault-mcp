/**
 * CIP-018: Credential delivery recipes.
 *
 * A vault entry declares WHAT a secret is (its `credential_type`); the recipe
 * maps that intent to a safe delivery MECHANISM. Callers never pick a channel
 * or a file descriptor — stdin and askpass are the hidden engine, env is the
 * backward-compatible default.
 *
 * Adding a credential type later (docker-login, db-password, …) is a one-line
 * entry here; nothing else changes.
 */

export type Mechanism = 'env' | 'stdin' | 'askpass';

export interface Recipe {
  /** recipe id === a vault entry's credential_type */
  id: string;
  /** human label shown in the dashboard picker */
  label: string;
  mechanism: Mechanism;
  /** askpass only: the tool's askpass env var (SUDO_ASKPASS | SSH_ASKPASS | GIT_ASKPASS) */
  askpassVar?: string;
  /** askpass only: wrap the command so the tool has no controlling tty (ssh needs this) */
  wrap?: 'setsid';
  /** stdin only: terminate the secret with a newline (line-oriented prompts want it) */
  appendNewline?: boolean;
  /** one-line, NON-SECRET description echoed back to the caller for transparency */
  delivery: string;
}

export const RECIPES: Record<string, Recipe> = {
  generic: {
    id: 'generic',
    label: 'API key / generic',
    mechanism: 'env',
    delivery: 'Injected as a named environment variable.',
  },
  sudo: {
    id: 'sudo',
    label: 'Sudo password',
    mechanism: 'stdin',
    appendNewline: true,
    delivery: 'Piped to `sudo -S` over stdin — never placed in the environment.',
  },
  'ssh-passphrase': {
    id: 'ssh-passphrase',
    label: 'SSH key passphrase',
    mechanism: 'askpass',
    askpassVar: 'SSH_ASKPASS',
    wrap: 'setsid',
    delivery: 'Delivered via an SSH_ASKPASS helper reading a private pipe.',
  },
  git: {
    id: 'git',
    label: 'Git credential',
    mechanism: 'askpass',
    askpassVar: 'GIT_ASKPASS',
    delivery: 'Delivered via a GIT_ASKPASS helper reading a private pipe.',
  },
};

export function getRecipe(id: string): Recipe | undefined {
  return RECIPES[id];
}

export function recipeIds(): string[] {
  return Object.keys(RECIPES);
}
