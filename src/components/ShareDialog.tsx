/**
 * ShareDialog Component
 * 
 * Dialog for sharing a document with another Nostr user.
 * Supports npub, hex pubkey, and NIP-05 identifier input.
 */

import { Component, createSignal, Show, onCleanup } from 'solid-js';
import { parseRecipientInput, formatPubkey } from '../lib/nostr/nip05';
import { getSyncEngine } from '../lib/nostr/sync';
import { fetchUserProfile } from '../lib/nostr/login';
import { sanitizeImageUrl } from '../lib/security';
import type { NostrProfile } from '../lib/nostr/types';

/** Debounce between the last keystroke and recipient resolution. */
export const SHARE_VALIDATION_DEBOUNCE_MS = 500;

export type ShareDocumentFn = (
  pubkey: string, title: string, content: string, filePath: string,
) => Promise<{ eventId: string }>;

interface ShareDialogProps {
  /** File path being shared */
  filePath: string;
  /** File content */
  content: string;
  /** Document title (filename without extension) */
  title: string;
  /** Callback when dialog is closed */
  onClose: () => void;
  /** Callback when share is successful */
  onSuccess?: (eventId: string) => void;
  /** Recipient resolver; defaults to npub/hex/NIP-05 parsing. */
  resolveRecipient?: typeof parseRecipientInput;
  /** Sharing backend; defaults to the sync engine. */
  shareDocument?: ShareDocumentFn;
}

/**
 * A recipient key bound to the exact field text it was resolved from.
 * Sharing only proceeds while the field still holds that text, so a
 * resolution that finishes after the user edited or cleared the field can
 * never become the share target.
 */
interface ValidatedRecipient {
  readonly input: string;
  readonly pubkey: string;
}

const ShareDialog: Component<ShareDialogProps> = (props) => {
  const [recipientInput, setRecipientInput] = createSignal('');
  const [validated, setValidated] = createSignal<ValidatedRecipient | null>(null);
  const [recipientProfile, setRecipientProfile] = createSignal<NostrProfile | null>(null);
  const [isValidating, setIsValidating] = createSignal(false);
  const [validationError, setValidationError] = createSignal<string | null>(null);
  const [isSharing, setIsSharing] = createSignal(false);
  const [shareError, setShareError] = createSignal<string | null>(null);
  const [shareSuccess, setShareSuccess] = createSignal(false);

  // Every input change starts a new generation: the pending debounce is
  // cancelled and any in-flight resolution/profile result for an older
  // generation is discarded when it settles.
  let generation = 0;
  let validationTimeout: ReturnType<typeof setTimeout> | null = null;

  const cancelPendingValidation = () => {
    if (validationTimeout !== null) {
      clearTimeout(validationTimeout);
      validationTimeout = null;
    }
  };

  onCleanup(() => {
    cancelPendingValidation();
    generation += 1;
  });

  const normalizedInput = () => recipientInput().trim();

  /** The key to share with: only a validation of the text currently in the field. */
  const readyPubkey = (): string | null => {
    const current = validated();
    return current && current.input === normalizedInput() ? current.pubkey : null;
  };

  const validateRecipient = async (input: string, gen: number) => {
    const live = () => gen === generation;
    setIsValidating(true);
    try {
      const resolve = props.resolveRecipient ?? parseRecipientInput;
      const result = await resolve(input);
      if (!live()) return;

      if (!result.pubkey) {
        setValidationError(result.error || 'Invalid recipient');
        return;
      }

      const pubkey = result.pubkey;
      setValidated({ input, pubkey });
      setRecipientProfile({
        pubkey,
        name: result.type === 'nip05' ? input : undefined,
      });

      // Fetch full profile from relays; purely cosmetic, never changes the target.
      const relays = getSyncEngine().getConfig().relays;
      const profile = await fetchUserProfile(pubkey, relays);
      if (!live() || !profile) return;
      setRecipientProfile({
        pubkey,
        name: profile.displayName || profile.name,
        picture: profile.picture,
        nip05: profile.nip05,
      });
    } catch {
      if (live()) setValidationError('Failed to validate recipient');
    } finally {
      if (live()) setIsValidating(false);
    }
  };

  const handleInput = (value: string) => {
    cancelPendingValidation();
    const gen = ++generation;
    setRecipientInput(value);
    setValidated(null);
    setRecipientProfile(null);
    setValidationError(null);
    setIsValidating(false);

    const input = value.trim();
    if (!input) return;

    validationTimeout = setTimeout(() => {
      validationTimeout = null;
      void validateRecipient(input, gen);
    }, SHARE_VALIDATION_DEBOUNCE_MS);
  };

  const handleShare = async () => {
    const target = validated();
    // Bind the share to the validated {input, pubkey} pair of the current generation.
    if (!target || target.input !== normalizedInput() || isSharing() || shareSuccess()) return;

    setIsSharing(true);
    setShareError(null);

    try {
      const share: ShareDocumentFn = props.shareDocument
        ?? ((pubkey, title, content, filePath) => getSyncEngine().shareDocument(pubkey, title, content, filePath));

      const result = await share(
        target.pubkey,
        props.title,
        props.content,
        props.filePath
      );

      setShareSuccess(true);
      props.onSuccess?.(result.eventId);

      // Close dialog after short delay
      setTimeout(() => {
        props.onClose();
      }, 1500);
    } catch (err) {
      console.error('Failed to share document:', err);
      setShareError(err instanceof Error ? err.message : 'Failed to share document');
    } finally {
      setIsSharing(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      props.onClose();
    } else if (e.key === 'Enter' && readyPubkey() && !isSharing()) {
      void handleShare();
    }
  };

  return (
    <div class="modal-overlay" onClick={props.onClose} onKeyDown={handleKeyDown}>
      <div class="share-dialog" onClick={(e) => e.stopPropagation()}>
        <div class="share-dialog-header">
          <h3>Share Document</h3>
          <button class="modal-close" onClick={props.onClose}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        <div class="share-dialog-body">
          {/* Document preview */}
          <div class="share-document-preview">
            <div class="share-document-icon">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
                <polyline points="10 9 9 9 8 9"></polyline>
              </svg>
            </div>
            <div class="share-document-info">
              <div class="share-document-title">{props.title}</div>
              <div class="share-document-size">{props.content.length} characters</div>
            </div>
          </div>

          {/* Recipient input */}
          <div class="share-recipient-section">
            <label class="share-label">Share with</label>
            <div class="share-input-wrapper">
              <input
                type="text"
                class={`share-input ${validationError() ? 'error' : ''} ${readyPubkey() ? 'valid' : ''}`}
                placeholder="npub1..., user@domain.com, or hex pubkey"
                aria-label="Share with"
                value={recipientInput()}
                onInput={(e) => handleInput(e.currentTarget.value)}
                disabled={isSharing() || shareSuccess()}
                autofocus
              />
              <Show when={isValidating()}>
                <div class="share-input-spinner">
                  <div class="spinner small"></div>
                </div>
              </Show>
              <Show when={readyPubkey() && !isValidating()}>
                <div class="share-input-check">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </div>
              </Show>
            </div>

            <Show when={validationError()}>
              <div class="share-error">{validationError()}</div>
            </Show>

            <Show when={recipientProfile() && readyPubkey()}>
              <div class="share-recipient-preview">
                <div class="share-recipient-avatar">
                  <Show when={sanitizeImageUrl(recipientProfile()?.picture)} fallback={
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                      <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                  }>
                    <img src={sanitizeImageUrl(recipientProfile()?.picture)} alt="" />
                  </Show>
                </div>
                <div class="share-recipient-info">
                  <Show when={recipientProfile()?.name}>
                    <div class="share-recipient-name">{recipientProfile()!.name}</div>
                  </Show>
                  <div class="share-recipient-pubkey">{formatPubkey(readyPubkey()!, 12)}</div>
                </div>
              </div>
            </Show>
          </div>

          <Show when={shareError()}>
            <div class="share-error-message">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
              </svg>
              {shareError()}
            </div>
          </Show>

          <Show when={shareSuccess()}>
            <div class="share-success-message">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
              Document shared successfully!
            </div>
          </Show>
        </div>

        <div class="share-dialog-footer">
          <button class="setting-button secondary" onClick={props.onClose} disabled={isSharing()}>
            Cancel
          </button>
          <button
            class="setting-button"
            onClick={() => void handleShare()}
            disabled={!readyPubkey() || isSharing() || shareSuccess()}
          >
            <Show when={isSharing()}>
              <div class="spinner small"></div>
            </Show>
            <Show when={!isSharing() && !shareSuccess()}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path>
                <polyline points="16 6 12 2 8 6"></polyline>
                <line x1="12" y1="2" x2="12" y2="15"></line>
              </svg>
              Share
            </Show>
            <Show when={shareSuccess()}>
              Shared!
            </Show>
          </button>
        </div>
      </div>
    </div>
  );
};

export default ShareDialog;
