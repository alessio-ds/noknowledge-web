/** Wire-layer error types, mirroring the Python reference. */

export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WireError';
  }
}

export class TransportError extends WireError {
  constructor(message: string) {
    super(message);
    this.name = 'TransportError';
  }
}

export class RelayHTTPError extends WireError {
  readonly status: number;
  readonly detail: string;
  constructor(status: number, detail = '') {
    super(`relay returned ${status}: ${detail}`);
    this.name = 'RelayHTTPError';
    this.status = status;
    this.detail = detail;
  }
}

export class RelayNotFound extends RelayHTTPError {
  constructor(status: number, detail = '') {
    super(status, detail);
    this.name = 'RelayNotFound';
  }
}

export class RelayUnauthorized extends RelayHTTPError {
  constructor(status: number, detail = '') {
    super(status, detail);
    this.name = 'RelayUnauthorized';
  }
}

export class RelayQuotaExceeded extends RelayHTTPError {
  constructor(status: number, detail = '') {
    super(status, detail);
    this.name = 'RelayQuotaExceeded';
  }
}

export class AllRelaysFailed extends WireError {
  constructor(message: string) {
    super(message);
    this.name = 'AllRelaysFailed';
  }
}
