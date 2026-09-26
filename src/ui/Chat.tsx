import { useCallback, useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { Client } from '../core/client';
import { deleteAccount, type UnlockedAccount } from '../core/accountService';
import { getRelays, setRelays } from '../core/config';
import type { DeviceEntry } from '../core/devices';
import { HistoryError, exportHistory, importHistory } from '../core/history';
import type { SyncRequest, SyncStatus } from '../core/sync';
import type { Contact, Message } from '../core/store';
import { CopyButton, ErrorText, Modal, QrCode, Spinner } from './components';

type Status = 'connecting' | 'online' | 'offline';

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function describeSince(since: number): string {
  if (!since) return 'everything';
  const days = Math.max(1, Math.round((Date.now() - since) / (24 * 3600 * 1000)));
  return `the last ${days} day${days === 1 ? '' : 's'}`;
}

function stateMark(state: string | null): string {
  if (state === 'read' || state === 'delivered') return '✓✓';
  return '✓';
}

export function Chat({
  session,
  onLock,
  onSessionChange,
}: {
  session: UnlockedAccount;
  onLock: () => void;
  onSessionChange: (account: UnlockedAccount) => void;
}) {
  const client = session.client;
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [previews, setPreviews] = useState<Record<string, Message | null>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [text, setText] = useState('');
  const [status, setStatus] = useState<Status>('connecting');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCard, setShowCard] = useState(false);
  const [showDevices, setShowDevices] = useState(false);
  const [devices, setDevices] = useState<DeviceEntry[]>([]);
  const [thisDevice, setThisDevice] = useState<string | null>(null);
  const [historyRange, setHistoryRange] = useState('30');
  const [historyPassphrase, setHistoryPassphrase] = useState('');
  const [historyStatus, setHistoryStatus] = useState<string | null>(null);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [cacheStats, setCacheStats] = useState({ chunks: 0, bytes: 0 });
  const [syncStates, setSyncStates] = useState<SyncStatus[]>([]);
  const [syncRequests, setSyncRequests] = useState<SyncRequest[]>([]);
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncNote, setSyncNote] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [cardText, setCardText] = useState('');
  const [addText, setAddText] = useState('');
  const [relaysText, setRelaysText] = useState(getRelays().join('\n'));
  const [scanning, setScanning] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState<{ id: string; done: number; total: number } | null>(null);

  const fileRef = useRef<HTMLInputElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const selectedRef = useRef<string | null>(null);
  selectedRef.current = selected;

  const refreshContacts = useCallback(async () => {
    const list = await client.listContacts();
    setContacts(list);
    const nextPreviews: Record<string, Message | null> = {};
    for (const contact of list) {
      const history = await client.messages(contact.id);
      nextPreviews[contact.id] = history.length > 0 ? history[history.length - 1] : null;
    }
    setPreviews(nextPreviews);
    return list;
  }, [client]);

  const refreshMessages = useCallback(
    async (contactId: string) => {
      const list = await client.messages(contactId);
      setMessages(list);
      return list;
    },
    [client],
  );

  // Receive loop: long-poll our own mailbox and refresh the view.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const tick = async () => {
      if (cancelled) return;
      try {
        const news = await client.sync(20);
        if (cancelled) return;
        setStatus('online');
        if (news.length > 0) {
          await refreshContacts();
          const current = selectedRef.current;
          if (current && news.some((message) => message.contact_id === current)) {
            await refreshMessages(current);
          }
        }
        void client.flushOutbox().catch(() => {});
      } catch {
        if (!cancelled) setStatus('offline');
      }
      if (!cancelled) timer = setTimeout(tick, 400);
    };

    void refreshContacts().then(() => tick());
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      client.close();
    };
  }, [client, refreshContacts, refreshMessages]);

  // Load the selected conversation and emit read receipts.
  useEffect(() => {
    if (!selected) {
      setMessages([]);
      return;
    }
    let alive = true;
    void (async () => {
      const list = await client.messages(selected);
      if (!alive) return;
      setMessages(list);
      let changed = false;
      for (const message of list) {
        if (message.direction === 'received' && message.state !== 'read') {
          try {
            await client.markRead(selected, message.id);
            changed = true;
          } catch {
            /* receipt is best-effort */
          }
        }
      }
      if (changed && alive) await refreshMessages(selected);
    })();
    return () => {
      alive = false;
    };
  }, [selected, client, refreshMessages]);

  const stopScan = useCallback(() => {
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    setScanning(false);
  }, []);

  useEffect(() => () => stopScan(), [stopScan]);

  const send = async () => {
    const body = text.trim();
    if (!body || !selected) return;
    setBusy(true);
    setError(null);
    try {
      await client.sendText(selected, body);
      setText('');
      await refreshMessages(selected);
      await refreshContacts();
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const attach = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file || !selected) return;
    setBusy(true);
    setError(null);
    try {
      const data = new Uint8Array(await file.arrayBuffer());
      await client.sendFile(selected, data, file.name, file.type || 'application/octet-stream');
      await refreshMessages(selected);
      await refreshContacts();
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const download = async (message: Message) => {
    setError(null);
    setDownloadProgress({ id: message.id, done: 0, total: 0 });
    try {
      const data = await client.downloadAttachment(message, (done, total) =>
        setDownloadProgress({ id: message.id, done, total }),
      );
      const attachment = ((message.body as any)?.attachment ?? {}) as Record<string, unknown>;
      const blob = new Blob([data as unknown as BlobPart], {
        type: (attachment.mime as string) || 'application/octet-stream',
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = (attachment.name as string) || 'attachment';
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setDownloadProgress(null);
    }
  };

  const openDevices = async () => {
    setShowDevices(true);
    setDevices([]);
    setError(null);
    setHistoryStatus(null);
    setSyncNote(null);
    try {
      const [listing, mine, chunks, bytes, states, requests] = await Promise.all([
        client.devices(),
        client.thisDeviceId(),
        client.store.localBlobCount(),
        client.store.localBlobBytes(),
        client.syncStatus(),
        client.historyRequests(),
      ]);
      setDevices(listing);
      setThisDevice(mine);
      setCacheStats({ chunks, bytes });
      setSyncStates(states);
      setSyncRequests(requests);
    } catch (caught) {
      setError((caught as Error).message);
    }
  };

  const runRequestHistory = async () => {
    setSyncBusy(true);
    setSyncNote(null);
    setError(null);
    try {
      const asked = await client.requestHistory(historySince());
      setSyncNote(
        asked.length > 0
          ? `Asked ${asked.length} device(s). Approve the request there: that click is what authorises the transfer.`
          : 'No other device answered yet. Keep this page open and make sure the other device is online.',
      );
      await refreshSyncState();
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setSyncBusy(false);
    }
  };

  const refreshSyncState = async () => {
    setSyncStates(await client.syncStatus());
    setSyncRequests(await client.historyRequests());
  };

  const runApprove = async (deviceId: string) => {
    setSyncBusy(true);
    setSyncNote(null);
    setError(null);
    try {
      const result = await client.approveHistory(deviceId);
      setSyncNote(
        `Sent ${result.items} item(s) to that device` +
          (result.skipped ? ` (${result.skipped} attachment(s) were over budget).` : '.') +
          ' Your future sent messages mirror to it too.',
      );
      await refreshSyncState();
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setSyncBusy(false);
    }
  };

  const runDeny = async (deviceId: string) => {
    setSyncBusy(true);
    setError(null);
    try {
      await client.denyHistory(deviceId);
      await refreshSyncState();
      setSyncNote('Request denied. Nothing was sent.');
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setSyncBusy(false);
    }
  };

  const historySince = (): number | null => {
    if (historyRange === 'all') return null;
    return Date.now() - Number(historyRange) * 24 * 3600 * 1000;
  };

  const downloadBlob = (data: Uint8Array, filename: string) => {
    const url = URL.createObjectURL(new Blob([data as unknown as BlobPart]));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const runExportHistory = async () => {
    setHistoryBusy(true);
    setHistoryStatus(null);
    setError(null);
    try {
      const data = await exportHistory(client, historyPassphrase, { sinceMs: historySince() });
      downloadBlob(data, `noknowledge-history-${new Date().toISOString().slice(0, 10)}.nkx`);
      setHistoryStatus(`Exported ${Math.round(data.length / 1024)} KB. Keep the passphrase: the file cannot be opened without it.`);
      setHistoryPassphrase('');
    } catch (caught) {
      setError(caught instanceof HistoryError ? caught.message : (caught as Error).message);
    } finally {
      setHistoryBusy(false);
    }
  };

  const runImportHistory = async (file: File) => {
    setHistoryBusy(true);
    setHistoryStatus(null);
    setError(null);
    try {
      const data = new Uint8Array(await file.arrayBuffer());
      const counts = await importHistory(client, data, historyPassphrase);
      setHistoryStatus(
        `Merged ${counts.messages} new message(s), ${counts.contacts} contact(s) and ${counts.chunks} attachment chunk(s).`,
      );
      setHistoryPassphrase('');
      await refreshContacts();
      const bytes = await client.store.localBlobBytes();
      setCacheStats({ chunks: await client.store.localBlobCount(), bytes });
    } catch (caught) {
      setError(caught instanceof HistoryError ? caught.message : (caught as Error).message);
    } finally {
      setHistoryBusy(false);
    }
  };

  const openCard = async () => {
    setShowCard(true);
    setCardText('');
    setError(null);
    try {
      setCardText(await client.cardString());
    } catch (caught) {
      setError((caught as Error).message);
    }
  };

  const submitAdd = async () => {
    if (!addText.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const contact = await client.addContact(addText.trim());
      setAddText('');
      setShowAdd(false);
      await refreshContacts();
      setSelected(contact.id);
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const saveSettings = async () => {
    const relays = relaysText
      .split('\n')
      .map((relay) => relay.trim())
      .filter(Boolean);
    if (relays.length === 0) {
      setError('At least one relay URL is required.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setRelays(relays);
      const next = new Client(session.identity, session.store, relays, session.meta.label);
      await next.provision();
      onSessionChange({ ...session, client: next });
      setShowSettings(false);
      setStatus('connecting');
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const removeAccount = async () => {
    const password = window.prompt('Enter your password to delete this account and all local data');
    if (!password) return;
    try {
      await deleteAccount(session.meta, password);
      onLock();
    } catch (caught) {
      window.alert((caught as Error).message);
    }
  };

  const scanFrame = useCallback(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA || video.videoWidth === 0) {
      rafRef.current = requestAnimationFrame(scanFrame);
      return;
    }
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const context = canvas.getContext('2d');
    if (!context) return;
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    const image = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(image.data, image.width, image.height);
    if (code?.data) {
      setAddText(code.data);
      stopScan();
      return;
    }
    rafRef.current = requestAnimationFrame(scanFrame);
  }, [stopScan]);

  // The <video> only exists once the modal has rendered, so attach the stream
  // here rather than in the click handler. Doing it from the handler with a 0ms
  // timeout was why iOS Safari and Samsung Internet showed a black preview: the
  // ref was still null, so srcObject was never set.
  useEffect(() => {
    if (!scanning) return;
    const video = videoRef.current;
    const stream = streamRef.current;
    if (!video || !stream) return;
    video.muted = true;
    video.setAttribute('playsinline', 'true');
    video.setAttribute('autoplay', 'true');
    video.srcObject = stream;
    const begin = () => {
      if (rafRef.current === null) rafRef.current = requestAnimationFrame(scanFrame);
    };
    const played = video.play();
    if (played && typeof played.then === 'function') played.then(begin).catch(begin);
    else begin();
    return () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [scanning, scanFrame]);

  const startScan = async () => {
    setError(null);
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('This browser will not give the page a camera (it must be served over HTTPS). Paste the card instead.');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
      });
      streamRef.current = stream;
      setScanning(true);
    } catch (caught) {
      const reason = (caught as Error)?.name === 'NotAllowedError' ? 'permission denied' : (caught as Error).message;
      setError(`Camera unavailable: ${reason}. Paste the card instead.`);
    }
  };

  const current = contacts.find((contact) => contact.id === selected) ?? null;

  return (
    <div className={`app${selected ? '' : ' show-list'}`}>
      <aside className="sidebar">
        <div className="sidebar-head">
          <div className="row between">
            <div style={{ minWidth: 0 }}>
              <div className="me" data-testid="self-name">
                {session.meta.label || 'me'}
              </div>
              <div className="id small muted" style={{ fontFamily: 'ui-monospace, Menlo, monospace' }}>
                {client.identityId}
              </div>
            </div>
            <div className="row" style={{ gap: 6 }}>
              <span className={`badge ${status === 'online' ? 'online' : status === 'offline' ? 'offline' : ''}`}>
                {status}
              </span>
              <button
                className="icon"
                data-testid="open-settings"
                aria-label="Settings"
                title="Settings"
                onClick={() => {
                  setShowSettings(true);
                  setError(null);
                }}
              >
                ⚙
              </button>
            </div>
          </div>
          <div className="sidebar-actions" data-testid="sidebar-actions">
            <button className="secondary small" data-testid="my-card" onClick={openCard}>
              My card
            </button>
            <button
              className="secondary small"
              data-testid="my-devices"
              onClick={() => void openDevices()}
            >
              Devices
            </button>
            <button
              className="secondary small"
              data-testid="open-add"
              onClick={() => {
                setShowAdd(true);
                setError(null);
              }}
            >
              Add contact
            </button>
          </div>
        </div>
        <div className="contacts">
          {contacts.length === 0 && (
            <p className="small muted" style={{ padding: 14 }}>
              No contacts yet. Share your card, or add someone else&apos;s.
            </p>
          )}
          {contacts.map((contact) => {
            const preview = previews[contact.id];
            const snippet = preview
              ? preview.type === 'file'
                ? '📎 attachment'
                : String((preview.body as any)?.text ?? '')
              : contact.id.slice(0, 10);
            return (
              <div
                key={contact.id}
                className={`contact${contact.id === selected ? ' active' : ''}`}
                data-testid="contact"
                onClick={() => setSelected(contact.id)}
              >
                <div className="name">{contact.nickname || contact.id.slice(0, 8)}</div>
                <div className="preview">{snippet}</div>
              </div>
            );
          })}
        </div>
      </aside>

      <main className="chat">
        {current ? (
          <>
            <div className="chat-head">
              <div>
                <div className="me">{current.nickname || current.id.slice(0, 8)}</div>
                <div className="id small muted" style={{ fontFamily: 'ui-monospace, Menlo, monospace' }}>
                  {current.id}
                </div>
              </div>
              <button className="ghost small" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
            <div className="messages" data-testid="messages">
              {messages.map((message) => {
                const sent = message.direction === 'sent';
                const attachment = ((message.body as any)?.attachment ?? null) as Record<string, unknown> | null;
                const caption = String((message.body as any)?.caption ?? '');
                return (
                  <div key={message.id} className={`bubble${sent ? ' sent' : ''}`} data-testid="bubble">
                    {message.type === 'file' && attachment ? (
                      <div>
                        <div className="attachment">
                          <span>📎</span>
                          <div className="grow">
                            <div>{String(attachment.name ?? 'attachment')}</div>
                            <div className="small muted">{formatSize(Number(attachment.size ?? 0))}</div>
                          </div>
                          {!sent && (
                            <button
                              className="secondary small"
                              data-testid="download"
                              disabled={downloadProgress?.id === message.id}
                              onClick={() => void download(message)}
                            >
                              {downloadProgress?.id === message.id
                                ? downloadProgress.total > 0
                                  ? `Downloading ${downloadProgress.done}/${downloadProgress.total}`
                                  : 'Downloading…'
                                : 'Download'}
                            </button>
                          )}
                        </div>
                        {caption ? (
                          <div className="text" style={{ marginTop: 6 }}>
                            {caption}
                          </div>
                        ) : null}
                      </div>
                    ) : (
                      <div className="text">{String((message.body as any)?.text ?? '')}</div>
                    )}
                    <div className="meta">
                      <span>{formatTime(message.ts)}</span>
                      {sent ? <span title={message.state ?? 'sent'}>{stateMark(message.state)}</span> : null}
                    </div>
                  </div>
                );
              })}
              {messages.length === 0 && (
                <div className="empty">
                  No messages yet. Say hello — the first message carries your contact card.
                </div>
              )}
            </div>
            <div className="composer">
              <textarea
                data-testid="composer"
                value={text}
                onChange={(event) => setText(event.target.value)}
                placeholder="Write a message…"
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    void send();
                  }
                }}
              />
              <input
                ref={fileRef}
                data-testid="attach-input"
                type="file"
                style={{ display: 'none' }}
                onChange={(event) => void attach(event)}
              />
              <button className="secondary" onClick={() => fileRef.current?.click()} disabled={busy}>
                Attach
              </button>
              <button data-testid="send" onClick={() => void send()} disabled={busy || !text.trim()}>
                Send
              </button>
            </div>
            <ErrorText error={error} />
          </>
        ) : (
          <div className="empty">
            <div>
              <h2>Select a contact</h2>
              <p className="muted">or add one with a card from someone you trust.</p>
            </div>
          </div>
        )}
      </main>

      {showCard && (
        <Modal title="My contact card" onClose={() => setShowCard(false)}>
          <p className="small muted">
            Share this with someone you want to talk to. It contains your public keys, a prekey
            handle, your mailbox write capability, and your relays — nothing secret.
          </p>
          {cardText ? (
            <>
              <QrCode text={cardText} />
              <textarea readOnly value={cardText} rows={4} className="card-string" data-testid="card-string" />
              <div className="row" style={{ marginTop: 10 }}>
                <CopyButton text={cardText} label="Copy card" />
              </div>
            </>
          ) : (
            <Spinner label="Preparing card…" />
          )}
          <ErrorText error={error} />
        </Modal>
      )}

      {showDevices && (
        <Modal title="My devices" onClose={() => setShowDevices(false)}>
          <p className="small muted">
            Every device on this account gets its own encrypted copy of anything sent to you.
            Restoring your seed phrase in another browser adds it here — with no history from
            before it joined.
          </p>
          {devices.length === 0 ? (
            <Spinner label="Asking the relay…" />
          ) : (
            <ul className="device-list" data-testid="device-list">
              {devices.map((device) => {
                const state = syncStates.find((item) => item.device_id === device.deviceId);
                const notes: string[] = [];
                if (device.deviceId !== thisDevice) {
                  if (!state || !state.has_keys) notes.push('no sync keys yet — update that device');
                  else if (state.approved) notes.push('history approved');
                  else notes.push('not approved');
                  if (state && state.received > 0) {
                    notes.push(`received ${state.received}/${state.expected || '?'} items`);
                  }
                }
                return (
                  <li key={device.deviceId}>
                    <div className="name">
                      {device.name || 'unnamed device'}
                      {device.deviceId === thisDevice && <span className="muted"> · this device</span>}
                    </div>
                    <div className="small muted mono">{device.deviceId}</div>
                    {notes.length > 0 && <div className="small muted">{notes.join(' · ')}</div>}
                    <div className="small muted">
                      mailbox {device.inbox.id.slice(0, 12)}… → {device.relays.join(', ') || 'these relays'}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          {syncRequests.length > 0 && (
            <>
              <h3 className="history-head">Waiting for your approval</h3>
              <ul className="device-list" data-testid="sync-requests">
                {syncRequests.map((request) => (
                  <li key={request.device_id}>
                    <div className="name">
                      {request.name || 'unnamed device'}
                      <span className="small muted">
                        {' '}
                        asked for {describeSince(request.since)}
                      </span>
                    </div>
                    <div className="row" style={{ marginTop: 6 }}>
                      <button
                        className="small"
                        data-testid={`approve-${request.device_id}`}
                        disabled={syncBusy}
                        onClick={() => void runApprove(request.device_id)}
                      >
                        Approve
                      </button>
                      <button
                        className="secondary small"
                        disabled={syncBusy}
                        onClick={() => void runDeny(request.device_id)}
                      >
                        Deny
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
              <p className="small muted">
                Approving sends that device the history it asked for, and mirrors your future sent
                messages to it. A stolen seed phrase cannot do this on its own: it needs a click here.
              </p>
            </>
          )}

          <h3 className="history-head">History</h3>
          <p className="small muted">
            {cacheStats.chunks} attachment chunk(s) cached locally (
            {(cacheStats.bytes / (1024 * 1024)).toFixed(1)} MB). An export file is encrypted with a
            passphrase you choose and carries contacts, messages and those attachments; importing
            merges it here without creating duplicates.
          </p>
          <div className="row">
            <select
              data-testid="history-range"
              value={historyRange}
              onChange={(event) => setHistoryRange(event.target.value)}
            >
              <option value="30">Last 30 days</option>
              <option value="60">Last 60 days</option>
              <option value="90">Last 90 days</option>
              <option value="all">Everything</option>
            </select>
          </div>
          <div className="row" style={{ marginTop: 8 }}>
            <input
              type="password"
              data-testid="history-passphrase"
              placeholder="Passphrase for the file"
              value={historyPassphrase}
              onChange={(event) => setHistoryPassphrase(event.target.value)}
            />
          </div>
          <div className="row" style={{ marginTop: 8 }}>
            <button
              className="secondary small"
              data-testid="request-history"
              disabled={syncBusy || devices.length < 2}
              onClick={() => void runRequestHistory()}
            >
              Request history…
            </button>
            <button
              className="secondary small"
              data-testid="export-history"
              disabled={historyBusy || !historyPassphrase}
              onClick={() => void runExportHistory()}
            >
              Export…
            </button>
            <label className="secondary small file-button">
              Import…
              <input
                type="file"
                accept=".nkx,application/octet-stream"
                data-testid="import-history"
                disabled={historyBusy || !historyPassphrase}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = '';
                  if (file) void runImportHistory(file);
                }}
              />
            </label>
          </div>
          {historyStatus && (
            <p className="small ok" data-testid="history-status">
              {historyStatus}
            </p>
          )}
          {syncNote && (
            <p className="small ok" data-testid="sync-note">
              {syncNote}
            </p>
          )}
          <ErrorText error={error} />
        </Modal>
      )}

      {showAdd && (
        <Modal
          title="Add a contact"
          onClose={() => {
            stopScan();
            setShowAdd(false);
          }}
        >
          <p className="small muted">Paste a card, or scan the QR it came from.</p>
          <textarea
            data-testid="add-card"
            value={addText}
            onChange={(event) => setAddText(event.target.value)}
            rows={4}
            placeholder="nk://1/…"
          />
          <div className="row" style={{ marginTop: 10 }}>
            <button data-testid="submit-add" onClick={() => void submitAdd()} disabled={busy || !addText.trim()}>
              Add contact
            </button>
            {!scanning ? (
              <button className="secondary" onClick={() => void startScan()}>
                Scan QR
              </button>
            ) : (
              <button className="secondary" onClick={stopScan}>
                Stop camera
              </button>
            )}
          </div>
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            style={{ marginTop: 12, display: scanning ? 'block' : 'none' }}
          />
          <canvas ref={canvasRef} style={{ display: 'none' }} />
          <ErrorText error={error} />
        </Modal>
      )}

      {showSettings && (
        <Modal title="Settings" onClose={() => setShowSettings(false)} wide>
          <label>Relays (one URL per line)</label>
          <textarea value={relaysText} onChange={(event) => setRelaysText(event.target.value)} rows={4} />
          <p className="small muted">
            Writing to all relays replicates your messages; reading uses whichever answers. Changing
            this re-registers your mailbox and republishes your prekeys.
          </p>
          <div className="row" style={{ marginTop: 12 }}>
            <button onClick={() => void saveSettings()} disabled={busy}>
              Save relays
            </button>
            <button className="ghost" onClick={onLock}>
              Sign out
            </button>
            <span className="grow" />
            <button className="ghost" onClick={() => void removeAccount()}>
              Delete account
            </button>
          </div>
          <ErrorText error={error} />
        </Modal>
      )}
    </div>
  );
}
