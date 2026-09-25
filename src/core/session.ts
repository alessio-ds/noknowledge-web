/** A live Double Ratchet session bound to a contact. */

import { b64d, b64e } from '../crypto/encoding';
import { Ratchet, RatchetState } from '../crypto/ratchet';

export class Session {
  constructor(
    public sid: Uint8Array,
    public ratchet: Ratchet,
    public sk: Uint8Array | null = null,
    public init: Record<string, unknown> | null = null,
    public established = false,
  ) {}

  /** True until the peer has confirmed the session by any message. */
  get isPending(): boolean {
    return !this.established;
  }

  toDict(): Record<string, unknown> {
    return {
      sid: b64e(this.sid),
      state: this.ratchet.state.toDict(),
      sk: this.sk ? b64e(this.sk) : null,
      init: this.init,
      established: this.established,
    };
  }

  static fromDict(data: any): Session {
    return new Session(
      b64d(String(data.sid)),
      new Ratchet(RatchetState.fromDict(data.state)),
      data.sk ? b64d(String(data.sk)) : null,
      data.init ?? null,
      Boolean(data.established),
    );
  }
}
