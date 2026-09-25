/** Backend interface and shared value types for relay access. */

import { b64d, b64e } from '../../crypto/encoding';
import { randomBytes } from '../../crypto/random';

export const MAILBOX_ID_SIZE = 16;
export const TOKEN_SIZE = 32;
export const CHUNK_ID_SIZE = 16;

/** An address plus the capabilities needed to use it.
 *
 * A recipient holds both read and write tokens. A sender, who learns the
 * address from a contact card, holds only the mailbox id and write token. */
export class MailboxCapability {
  constructor(
    public mailboxId: string,
    public writeToken: string,
    public readToken: string | null = null,
  ) {}

  static generate(): MailboxCapability {
    return new MailboxCapability(
      b64e(randomBytes(MAILBOX_ID_SIZE)),
      b64e(randomBytes(TOKEN_SIZE)),
      b64e(randomBytes(TOKEN_SIZE)),
    );
  }

  toJson(): Record<string, string> {
    const payload: Record<string, string> = {
      mailbox_id: this.mailboxId,
      write_token: this.writeToken,
    };
    if (this.readToken !== null) payload.read_token = this.readToken;
    return payload;
  }

  /** The write-only view that goes into a contact card. */
  cardView(): { id: string; w: string } {
    return { id: this.mailboxId, w: this.writeToken };
  }

  static fromCardView(view: { id: string; w: string }): MailboxCapability {
    return new MailboxCapability(String(view.id), String(view.w));
  }

  static fromJson(payload: any, withRead = true): MailboxCapability {
    const read = withRead ? payload?.read_token : null;
    const capability = new MailboxCapability(
      String(payload?.mailbox_id),
      String(payload?.write_token),
      read ? String(read) : null,
    );
    capability.validate();
    return capability;
  }

  validate(): void {
    for (const [name, token] of [
      ['write_token', this.writeToken],
      ['read_token', this.readToken],
    ] as const) {
      if (token === null) continue;
      let raw: Uint8Array;
      try {
        raw = b64d(token);
      } catch {
        throw new Error(`${name} is not valid base64url`);
      }
      if (raw.length !== TOKEN_SIZE) throw new Error(`${name} has the wrong length`);
    }
  }
}

/** One blob as seen from one relay. */
export interface FetchedMessage {
  relay: string;
  seq: number;
  blob: Uint8Array;
}
