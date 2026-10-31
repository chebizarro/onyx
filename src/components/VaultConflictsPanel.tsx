/**
 * VaultConflictsPanel
 *
 * Inspect durable vault conflicts (file, directory and deletion-only) and,
 * for the owner on the publishing device, resolve them. A directory choice
 * supersedes descendant choices; inconsistent sets are rejected before the
 * engine is called. Members get a read-only view.
 */

import { Component, For, Show, createMemo, createSignal } from 'solid-js';
import { createStore } from 'solid-js/store';
import { formatPubkey } from '../lib/nostr/nip05';
import type {
  VaultConflictResolution, VaultEngine, VaultEngineSnapshot,
} from '../lib/vault/engine-api';
import type { VaultId } from '../lib/vault/types';
import {
  basenameOf, createProfileMap, defaultProfileRelays, describeVaultError, lookupProfile,
  useSnapshot, validateBasename, type ProfileLookup, type VaultConflictView,
} from './vault-ui';
import './vault.css';

export type VaultConflictAction = VaultConflictResolution['action'];

export interface VaultConflictsPanelProps {
  engine: Pick<VaultEngine, 'subscribe' | 'resolveConflicts'>;
  vaultId: VaultId;
  snapshot?: VaultEngineSnapshot;
  conflicts: readonly VaultConflictView[];
  /** Open the other version (file sibling, or materialise a directory subtree on demand). */
  onOpenVersion?: (conflict: VaultConflictView) => void;
  /** Prefill text for a manual merge, typically the selected-view file. */
  loadMergeText?: (conflict: VaultConflictView) => Promise<string>;
  profileRelays?: readonly string[];
  lookupProfile?: ProfileLookup;
  onResolved?: (vaultId: VaultId, resolutions: readonly VaultConflictResolution[]) => void;
  onClose?: () => void;
}

interface Choice {
  action: VaultConflictAction;
  newBasename: string;
  mergeText: string;
}

const ACTION_LABELS: Record<VaultConflictAction, string> = {
  'keep-view': 'Keep selected view',
  'use-other': 'Use other version',
  delete: 'Delete',
  'keep-both': 'Keep both',
  'manual-merge': 'Save a merged file',
};

export function availableActions(conflict: VaultConflictView): VaultConflictAction[] {
  const both = conflict.inView && conflict.inOther;
  const actions: VaultConflictAction[] = ['keep-view', 'use-other', 'delete'];
  if (both) actions.push('keep-both');
  if (both && conflict.kind === 'file') actions.push('manual-merge');
  return actions;
}

function parentOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

function joinPath(parent: string, name: string): string {
  return parent ? `${parent}/${name}` : name;
}

const VaultConflictsPanel: Component<VaultConflictsPanelProps> = (props) => {
  const snapshot = useSnapshot(props.engine, () => props.snapshot);
  const vault = createMemo(() => snapshot().vaults.find((v) => v.vaultId === props.vaultId));
  const isOwner = () => vault()?.authority === 'owner';
  const isPublisher = () => vault()?.publisher?.isCurrentDevice === true;
  const [choices, setChoices] = createStore<Record<string, Choice | undefined>>({});
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);

  const profiles = createProfileMap(
    () => props.conflicts.map((c) => c.writer),
    () => props.profileRelays ?? defaultProfileRelays(snapshot(), props.vaultId),
    props.lookupProfile ?? lookupProfile,
  );
  const writerName = (pubkey: string) => profiles().get(pubkey)?.name || formatPubkey(pubkey, 8);

  /** The directory conflict whose choice supersedes this one, if any. */
  const supersededBy = (conflict: VaultConflictView): VaultConflictView | undefined =>
    props.conflicts.find((other) => other.conflictId !== conflict.conflictId
      && other.kind === 'directory'
      && choices[other.conflictId] !== undefined
      && conflict.path.startsWith(`${other.path}/`));

  const setAction = (conflict: VaultConflictView, action: VaultConflictAction | '') => {
    setError(null);
    if (!action) {
      setChoices(conflict.conflictId, undefined);
      return;
    }
    const prev = choices[conflict.conflictId];
    setChoices(conflict.conflictId, {
      action,
      newBasename: prev?.newBasename ?? '',
      mergeText: prev?.mergeText ?? '',
    });
    if (action === 'manual-merge' && props.loadMergeText && !prev?.mergeText) {
      void props.loadMergeText(conflict).then(
        (text) => {
          const current = choices[conflict.conflictId];
          if (current?.action === 'manual-merge' && !current.mergeText) {
            setChoices(conflict.conflictId, 'mergeText', text);
          }
        },
        () => undefined,
      );
    }
  };

  /** Per-conflict validation errors for the current choice set. */
  const validation = createMemo(() => {
    const errors = new Map<string, string>();
    const targets = new Map<string, string>();
    const existing = new Set(props.conflicts.map((c) => c.path));
    for (const conflict of props.conflicts) {
      const choice = choices[conflict.conflictId];
      if (!choice || supersededBy(conflict)) continue;
      if (!availableActions(conflict).includes(choice.action)) {
        errors.set(conflict.conflictId, 'That choice is not available for this conflict.');
      } else if (choice.action === 'keep-both') {
        const name = choice.newBasename;
        const nameError = validateBasename(name, basenameOf(conflict.path));
        const target = joinPath(parentOf(conflict.path), name);
        if (nameError) errors.set(conflict.conflictId, nameError);
        else if (existing.has(target)) errors.set(conflict.conflictId, 'Another conflicting item already uses that name.');
        else if (targets.has(target)) errors.set(conflict.conflictId, 'Two choices use the same new name.');
        else targets.set(target, conflict.conflictId);
      }
    }
    return errors;
  });

  const resolutions = (): VaultConflictResolution[] => props.conflicts.flatMap((conflict): VaultConflictResolution[] => {
    const choice = choices[conflict.conflictId];
    if (!choice || supersededBy(conflict)) return [];
    const conflictId = conflict.conflictId;
    switch (choice.action) {
      case 'keep-both': return [{ conflictId, action: 'keep-both', newBasename: choice.newBasename }];
      case 'manual-merge': return [{ conflictId, action: 'manual-merge', bytes: new TextEncoder().encode(choice.mergeText) }];
      default: return [{ conflictId, action: choice.action }];
    }
  });

  const canResolve = () => isOwner() && isPublisher();
  const canApply = () => canResolve() && !busy() && resolutions().length > 0 && validation().size === 0;

  const apply = async () => {
    if (!canApply()) return;
    const set = resolutions();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await props.engine.resolveConflicts(props.vaultId, set);
      setChoices(Object.fromEntries(Object.keys(choices).map((k) => [k, undefined])));
      setNotice(`${set.length} conflict(s) resolved.`);
      props.onResolved?.(props.vaultId, set);
    } catch (err) {
      setError(describeVaultError(err));
    } finally {
      setBusy(false);
    }
  };

  const presence = (c: VaultConflictView): string => {
    if (c.inView && c.inOther) return c.kind === 'directory' ? 'Folder differs between versions' : 'File differs between versions';
    if (c.inView) return 'Deleted in the other version';
    if (c.inOther) return 'Deleted in the selected view';
    return 'Missing from both versions';
  };

  return (
    <section class="vault-conflicts" aria-label="Vault conflicts">
      <header class="vault-panel__header">
        <div class="vault-panel__title">
          <h3>Conflicts</h3>
          <span class="vault-badge vault-badge--conflict">{props.conflicts.length}</span>
        </div>
        <Show when={props.onClose}>
          <button class="modal-close" aria-label="Close" onClick={() => props.onClose?.()}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </Show>
      </header>

      <Show when={!isOwner()}>
        <p class="vault-note" data-testid="vault-conflicts-readonly">
          Only the owner can resolve conflicts in the shared view. You can open other versions and save your
          own revised copy, which is published as your proposal.
        </p>
      </Show>
      <Show when={isOwner() && !isPublisher()}>
        <p class="vault-note">
          Resolutions are published from the publishing device. Take over publishing on this device to resolve here.
        </p>
      </Show>

      <Show when={props.conflicts.length > 0} fallback={<div class="vault-panel__empty">No conflicts.</div>}>
        <ul class="vault-conflict-list">
          <For each={props.conflicts}>
            {(conflict) => {
              const choice = () => choices[conflict.conflictId];
              const superseded = () => supersededBy(conflict);
              const rowError = () => validation().get(conflict.conflictId);
              const deletionOnly = () => !(conflict.inView && conflict.inOther);
              return (
                <li
                  class={`vault-conflict ${deletionOnly() ? 'vault-conflict--deletion' : ''} ${superseded() ? 'vault-conflict--superseded' : ''}`}
                  data-conflict-id={conflict.conflictId}
                >
                  <div class="vault-conflict__head">
                    <span class="vault-tag">{conflict.kind === 'directory' ? 'folder' : 'file'}</span>
                    <span class="vault-mono vault-conflict__path">{conflict.path}</span>
                  </div>
                  <div class="vault-conflict__meta">
                    {presence(conflict)}. Other version by {writerName(conflict.writer)}, revision {conflict.seq.toString()}.
                  </div>
                  <Show when={conflict.hashedStorage}>
                    <div class="vault-field__hint">This name cannot be stored locally; the version is kept under a hashed name.</div>
                  </Show>
                  <div class="vault-actions">
                    <Show when={conflict.inOther && props.onOpenVersion && (conflict.kind === 'directory' || conflict.alternatePath)}>
                      <button class="setting-button small secondary" onClick={() => props.onOpenVersion?.(conflict)}>
                        Open other version
                      </button>
                    </Show>
                    <Show when={canResolve() && !superseded()}>
                      <select
                        class="vault-select"
                        aria-label={`Resolution for ${conflict.path}`}
                        value={choice()?.action ?? ''}
                        disabled={busy()}
                        onChange={(e) => setAction(conflict, e.currentTarget.value as VaultConflictAction | '')}
                      >
                        <option value="">Decide later</option>
                        <For each={availableActions(conflict)}>
                          {(action) => <option value={action}>{ACTION_LABELS[action]}</option>}
                        </For>
                      </select>
                    </Show>
                  </div>
                  <Show when={superseded()}>
                    {(dir) => <div class="vault-field__hint">Covered by the choice for folder {dir().path}.</div>}
                  </Show>
                  <Show when={canResolve() && !superseded() && choice()?.action === 'keep-both'}>
                    <label class="vault-field">
                      <span class="vault-field__label">New name for the other version</span>
                      <input
                        class="vault-input"
                        type="text"
                        aria-label={`New name for ${conflict.path}`}
                        value={choice()?.newBasename ?? ''}
                        onInput={(e) => setChoices(conflict.conflictId, 'newBasename', e.currentTarget.value)}
                      />
                    </label>
                  </Show>
                  <Show when={canResolve() && !superseded() && choice()?.action === 'manual-merge'}>
                    <label class="vault-field">
                      <span class="vault-field__label">Merged content</span>
                      <textarea
                        class="vault-input vault-textarea"
                        aria-label={`Merged content for ${conflict.path}`}
                        value={choice()?.mergeText ?? ''}
                        onInput={(e) => setChoices(conflict.conflictId, 'mergeText', e.currentTarget.value)}
                      />
                    </label>
                  </Show>
                  <Show when={rowError()}>
                    <div class="vault-error">{rowError()}</div>
                  </Show>
                </li>
              );
            }}
          </For>
        </ul>
      </Show>

      <Show when={canResolve() && props.conflicts.length > 0}>
        <div class="vault-actions">
          <button class="setting-button" disabled={!canApply()} onClick={() => void apply()}>
            {busy() ? 'Resolving...' : `Apply ${resolutions().length} resolution(s)`}
          </button>
        </div>
        <p class="vault-field__hint">Losing versions are retained; nothing is removed from the servers.</p>
      </Show>

      <Show when={notice()}>
        <div class="vault-success" role="status">{notice()}</div>
      </Show>
      <Show when={error()}>
        <div class="vault-error" role="alert">{error()}</div>
      </Show>
    </section>
  );
};

export default VaultConflictsPanel;
