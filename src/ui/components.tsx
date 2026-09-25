import { useEffect, useState, type ReactNode } from 'react';
import QRCode from 'qrcode';

export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className={`modal${wide ? ' wide' : ''}`} onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="icon" onClick={onClose} aria-label="Close dialog">
            ×
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="spinner-wrap">
      <div className="spinner" />
      {label ? <span>{label}</span> : null}
    </div>
  );
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="secondary"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard can be blocked; the text is selectable anyway */
        }
      }}
    >
      {done ? 'Copied' : label}
    </button>
  );
}

export function QrCode({ text, size = 260 }: { text: string; size?: number }) {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    QRCode.toDataURL(text, {
      width: size,
      margin: 1,
      errorCorrectionLevel: 'L',
      color: { dark: '#0b0d10', light: '#ffffff' },
    })
      .then((value) => {
        if (alive) setUrl(value);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [text, size]);
  if (!url) return <Spinner />;
  return <img className="qr" src={url} width={size} height={size} alt="Contact card QR code" />;
}

export function ErrorText({ error }: { error: string | null }) {
  if (!error) return null;
  return <p className="error">{error}</p>;
}

export function ModalError({ error, children }: { error: string | null; children: ReactNode }) {
  return (
    <div>
      {children}
      <ErrorText error={error} />
      {children ? null : null}
    </div>
  );
}
