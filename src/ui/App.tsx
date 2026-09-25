import { useState } from 'react';
import type { UnlockedAccount } from '../core/accountService';
import { Chat } from './Chat';
import { Landing } from './Landing';

export function App() {
  const [session, setSession] = useState<UnlockedAccount | null>(null);

  if (session) {
    return (
      <Chat session={session} onLock={() => setSession(null)} onSessionChange={setSession} />
    );
  }
  return <Landing onUnlocked={setSession} />;
}
