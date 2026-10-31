import { createSignal, onCleanup } from 'solid-js';
import type { VaultEngine, VaultEngineSnapshot } from './engine-api';
import { getVaultEngine } from './engine';

/** Main-thread immutable snapshots. The component owns only this subscription. */
export function useVaultEngine(engine: Pick<VaultEngine, 'subscribe'> = getVaultEngine()) {
  const [snapshot, setSnapshot] = createSignal<VaultEngineSnapshot>();
  const unsubscribe = engine.subscribe(value => setSnapshot(() => value));
  onCleanup(unsubscribe);
  // subscribe emits synchronously before this accessor can be observed.
  return () => snapshot()!;
}
