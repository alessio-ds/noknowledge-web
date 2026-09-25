import { useState } from 'react';
import { Identity } from '../crypto/identity';
import {
  createAccount,
  importVaultAccount,
  listAccounts,
  unlockAccount,
  type AccountMeta,
  type UnlockedAccount,
} from '../core/accountService';
import { getRelays } from '../core/config';
import { CopyButton, ErrorText, Spinner } from './components';

type Mode = 'home' | 'create' | 'seed' | 'import' | 'vault' | 'unlock';

export function Landing({ onUnlocked }: { onUnlocked: (account: UnlockedAccount) => void }) {
  const [accounts, setAccounts] = useState<AccountMeta[]>(() => listAccounts());
  const [mode, setMode] = useState<Mode>('home');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [mnemonic, setMnemonic] = useState('');
  const [vaultJson, setVaultJson] = useState('');
  const [vaultPass, setVaultPass] = useState('');
  const [draft, setDraft] = useState<{ identity: Identity; mnemonic: string; name: string; password: string } | null>(null);
  const [target, setTarget] = useState<AccountMeta | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const relays = getRelays();

  const reset = () => {
    setError(null);
    setName('');
    setPassword('');
    setConfirm('');
    setMnemonic('');
    setVaultJson('');
    setVaultPass('');
    setDraft(null);
    setTarget(null);
  };

  const goHome = () => {
    reset();
    setAccounts(listAccounts());
    setMode('home');
  };

  const run = async (label: string, task: () => Promise<UnlockedAccount>) => {
    setBusy(label);
    setError(null);
    try {
      onUnlocked(await task());
    } catch (caught) {
      setError((caught as Error)?.message ?? String(caught));
    } finally {
      setBusy(null);
    }
  };

  const checkPassword = (): boolean => {
    if (password.length < 8) {
      setError('Use a password of at least 8 characters.');
      return false;
    }
    if (mode === 'create' && password !== confirm) {
      setError('Passwords do not match.');
      return false;
    }
    return true;
  };

  const startCreate = (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!checkPassword()) return;
    const identityName = name.trim() || 'me';
    const [identity, words] = Identity.generate(identityName);
    setDraft({ identity, mnemonic: words, name: identityName, password });
    setMnemonic(words);
    setMode('seed');
  };

  const finishCreate = () => {
    if (!draft) return;
    void run('Creating your identity…', () =>
      createAccount({ name: draft.name, password: draft.password, relays, mnemonic: draft.mnemonic }),
    );
  };

  const submitImport = (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!checkPassword()) return;
    void run('Importing your identity…', () =>
      createAccount({ name: name.trim() || 'me', password, relays, mnemonic: mnemonic.trim() }),
    );
  };

  const submitVault = (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!checkPassword()) return;
    void run('Importing your vault…', () =>
      importVaultAccount({
        name: name.trim() || 'me',
        password,
        vaultJson,
        vaultPassphrase: vaultPass || undefined,
        relays,
      }),
    );
  };

  const submitUnlock = (event: React.FormEvent) => {
    event.preventDefault();
    if (!target) return;
    void run('Unlocking…', () => unlockAccount(target, password, relays));
  };

  const downloadVault = () => {
    if (!draft) return;
    const data = draft.identity.toVault(draft.password);
    const blob = new Blob([data as unknown as BlobPart], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'identity.nk';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  if (busy) {
    return (
      <div className="center">
        <div className="card">
          <Spinner label={busy} />
          <ErrorText error={error} />
        </div>
      </div>
    );
  }

  return (
    <div className="center">
      <div className={`card${mode === 'seed' ? ' wide' : ''}`}>
        <h1 className="brand">noknowledge</h1>
        <p className="tagline">
          End-to-end encrypted, federated messaging. Your keys never leave this browser.
        </p>

        {mode === 'home' && (
          <div>
            {accounts.length > 0 && (
              <div className="stack" style={{ marginBottom: 18 }}>
                {accounts.map((account) => (
                  <div className="account" key={account.id}>
                    <div>
                      <div className="me">{account.label || account.id.slice(0, 8)}</div>
                      <div className="id">{account.id}</div>
                    </div>
                    <button
                      className="secondary"
                      onClick={() => {
                        reset();
                        setTarget(account);
                        setMode('unlock');
                      }}
                    >
                      Unlock
                    </button>
                  </div>
                ))}
              </div>
            )}
            <div className="stack">
              <button onClick={() => { reset(); setMode('create'); }}>Create a new identity</button>
              <button className="secondary" onClick={() => { reset(); setMode('import'); }}>
                Import from a seed phrase
              </button>
              <button className="secondary" onClick={() => { reset(); setMode('vault'); }}>
                Import a desktop vault (identity.nk)
              </button>
            </div>
            <p className="small muted" style={{ marginTop: 16 }}>
              Relays: {relays.join(', ')}
            </p>
          </div>
        )}

        {mode === 'create' && (
          <form onSubmit={startCreate}>
            <label>Display name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Alice" autoFocus />
            <label>Password (encrypts your local data)</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <label>Confirm password</label>
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            <ErrorText error={error} />
            <div className="row" style={{ marginTop: 18 }}>
              <button type="submit">Continue</button>
              <button type="button" className="ghost" onClick={goHome}>
                Back
              </button>
            </div>
            <p className="small muted" style={{ marginTop: 12 }}>
              There is no password reset: the seed phrase generated next is the only recovery.
            </p>
          </form>
        )}

        {mode === 'seed' && draft && (
          <div>
            <h2>Save your seed phrase</h2>
            <p className="small muted">
              These 24 words are your account. Write them down and keep them offline. Anyone who has
              them can read your messages; without them this account cannot be recovered.
            </p>
            <div className="mnemonic">
              {draft.mnemonic.split(' ').map((word, index) => (
                <span key={`${word}-${index}`}>
                  <b>{index + 1}</b>
                  {word}
                </span>
              ))}
            </div>
            <div className="row">
              <CopyButton text={draft.mnemonic} label="Copy seed phrase" />
              <button className="secondary" onClick={downloadVault}>
                Download identity.nk
              </button>
            </div>
            <div className="row" style={{ marginTop: 18 }}>
              <button onClick={finishCreate}>I saved it — continue</button>
              <button className="ghost" onClick={goHome}>
                Cancel
              </button>
            </div>
            <ErrorText error={error} />
          </div>
        )}

        {mode === 'import' && (
          <form onSubmit={submitImport}>
            <label>Display name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Alice" />
            <label>Seed phrase (24 words)</label>
            <textarea value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} rows={3} autoFocus />
            <label>Password (encrypts your local data)</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <ErrorText error={error} />
            <div className="row" style={{ marginTop: 18 }}>
              <button type="submit">Import</button>
              <button type="button" className="ghost" onClick={goHome}>
                Back
              </button>
            </div>
          </form>
        )}

        {mode === 'vault' && (
          <form onSubmit={submitVault}>
            <label>Display name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Alice" />
            <label>Vault contents (identity.nk JSON)</label>
            <textarea value={vaultJson} onChange={(e) => setVaultJson(e.target.value)} rows={5} />
            <label>Vault passphrase (if the vault is encrypted)</label>
            <input type="password" value={vaultPass} onChange={(e) => setVaultPass(e.target.value)} />
            <label>New local password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <ErrorText error={error} />
            <div className="row" style={{ marginTop: 18 }}>
              <button type="submit">Import</button>
              <button type="button" className="ghost" onClick={goHome}>
                Back
              </button>
            </div>
          </form>
        )}

        {mode === 'unlock' && target && (
          <form onSubmit={submitUnlock}>
            <h2>{target.label || target.id.slice(0, 8)}</h2>
            <p className="small muted">{target.id}</p>
            <label>Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            <ErrorText error={error} />
            <div className="row" style={{ marginTop: 18 }}>
              <button type="submit">Unlock</button>
              <button type="button" className="ghost" onClick={goHome}>
                Back
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
