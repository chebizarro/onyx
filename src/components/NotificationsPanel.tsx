/**
 * NotificationsPanel Component
 * 
 * Shows documents shared with the current user.
 * Displays sender info, document title, and allows preview/import.
 *
 * Vault invitations that have not been accepted never load a remote avatar
 * automatically: the picture URL is chosen by the inviter and loading it
 * would contact a host of their choosing before the user approved anything.
 * The owner's key fingerprint is always shown next to the profile name.
 */

import { Component, For, Show, createSignal } from 'solid-js';
import { formatPubkey } from '../lib/nostr/nip05';
import { sanitizeImageUrl } from '../lib/security';
import type { SharedDocument } from '../lib/nostr/types';
import type { VaultInvitationSummary } from '../lib/vault/engine-api';
import { createProfileMap, defaultProfileRelays, lookupProfile, shortVaultId, type ProfileLookup } from './vault-ui';
import KeyFingerprint from './KeyFingerprint';
import './vault.css';

interface NotificationsPanelProps {
  /** List of shared documents */
  sharedDocuments: SharedDocument[];
  /** Whether data is loading */
  isLoading: boolean;
  /** Callback when a document is clicked for preview */
  onPreview: (doc: SharedDocument) => void;
  /** Callback to refresh the list */
  onRefresh: () => void;
  /** Callback when panel is closed */
  onClose: () => void;
  /** Shared-vault invitations (shown in their own group; dismissed ones are hidden) */
  vaultInvitations?: readonly VaultInvitationSummary[];
  /** Callback when a vault invitation is opened for review */
  onPreviewVaultInvitation?: (invitation: VaultInvitationSummary) => void;
  /** Relays for profile lookups; defaults to the sync engine's relays */
  profileRelays?: readonly string[];
  lookupProfile?: ProfileLookup;
}

const NotificationsPanel: Component<NotificationsPanelProps> = (props) => {
  const visibleInvitations = () => (props.vaultInvitations ?? []).filter(inv => !inv.dismissed);
  const isInvitationUnread = (inv: VaultInvitationSummary) => !inv.read && !inv.accepted;
  const unreadCount = () => props.sharedDocuments.filter(d => !d.isRead).length
    + visibleInvitations().filter(isInvitationUnread).length;
  const totalCount = () => props.sharedDocuments.length + visibleInvitations().length;
  const showGroups = () => visibleInvitations().length > 0;

  // Invitations whose owner avatar the user explicitly asked to load (per invitation id).
  const [avatarsRequested, setAvatarsRequested] = createSignal<ReadonlySet<string>>(new Set());
  const requestAvatar = (invitationId: string) => {
    setAvatarsRequested((prev) => new Set(prev).add(invitationId));
  };

  // Profiles are looked up once per pubkey (cached, including failures)
  const senderProfiles = createProfileMap(
    () => [...new Set([
      ...props.sharedDocuments.map(d => d.senderPubkey),
      ...visibleInvitations().map(inv => inv.owner as string),
    ])],
    () => props.profileRelays ?? defaultProfileRelays(),
    props.lookupProfile ?? lookupProfile,
  );

  // Get profile for a sender, with fallback to embedded info
  const getSenderProfile = (doc: SharedDocument): { name?: string; picture?: string } => {
    const cached = senderProfiles().get(doc.senderPubkey);
    if (cached) {
      return { name: cached.name, picture: cached.picture };
    }
    // Fallback to embedded sharedBy info
    return { name: doc.data.sharedBy.name };
  };

  // Extract a clean display name from a shared document
  // Handles cases where title might be a full path (Windows or Unix) or have extension
  const getDisplayName = (doc: SharedDocument): string => {
    // Try title first, fall back to path
    let name = doc.title || doc.data.path || 'Untitled';
    
    // If it looks like a path (Windows or Unix), extract just the filename
    if (name.includes('/') || name.includes('\\')) {
      // Split on both forward and back slashes
      const parts = name.split(/[/\\]/);
      name = parts[parts.length - 1] || name;
    }
    
    // Remove file extension if present
    name = name.replace(/\.[^/.]+$/, '');
    
    return name || 'Untitled';
  };

  const formatTimeAgo = (timestamp: number): string => {
    const now = Math.floor(Date.now() / 1000);
    const diff = now - timestamp;

    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString();
  };

  return (
    <div class="notifications-panel">
      <div class="notifications-header">
        <div class="notifications-title">
          <h3>Shared with you</h3>
          <Show when={unreadCount() > 0}>
            <span class="notifications-badge">{unreadCount()}</span>
          </Show>
        </div>
        <div class="notifications-actions">
          <button 
            class="notifications-refresh" 
            onClick={props.onRefresh}
            disabled={props.isLoading}
            title="Refresh"
          >
            <svg 
              width="16" 
              height="16" 
              viewBox="0 0 24 24" 
              fill="none" 
              stroke="currentColor" 
              stroke-width="2"
              class={props.isLoading ? 'spinning' : ''}
            >
              <polyline points="23 4 23 10 17 10"></polyline>
              <polyline points="1 20 1 14 7 14"></polyline>
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
            </svg>
          </button>
          <button class="notifications-close" onClick={props.onClose}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
      </div>

      <div class="notifications-body">
        <Show when={props.isLoading && totalCount() === 0}>
          <div class="notifications-loading">
            <div class="spinner"></div>
            <span>Loading shared documents...</span>
          </div>
        </Show>

        <Show when={!props.isLoading && totalCount() === 0}>
          <div class="notifications-empty">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
            </svg>
            <p>Nothing shared with you yet</p>
            <span>When someone shares a document or vault, it will appear here</span>
          </div>
        </Show>

        <Show when={visibleInvitations().length > 0}>
          <div class="notifications-group-title">Vault invitations</div>
          <div class="notifications-list" aria-label="Vault invitations">
            <For each={visibleInvitations()}>
              {(inv) => {
                const ownerProfile = () => senderProfiles().get(inv.owner);
                const remotePicture = () => sanitizeImageUrl(ownerProfile()?.picture);
                // Accepted invitations belong to a vault the user already approved; anything else needs a click.
                const avatarAllowed = () => inv.accepted || avatarsRequested().has(inv.invitationId);
                const avatarSrc = () => (avatarAllowed() ? remotePicture() : undefined);
                return (
                  <div
                    class={`notification-item vault-invitation ${isInvitationUnread(inv) ? 'unread' : 'read'}`}
                    data-invitation-id={inv.invitationId}
                    onClick={() => props.onPreviewVaultInvitation?.(inv)}
                  >
                    <div class="notification-unread-dot">
                      <Show when={isInvitationUnread(inv)}>
                        <span></span>
                      </Show>
                    </div>
                    <div class="notification-avatar">
                      <Show when={avatarSrc()} fallback={
                        <Show when={!avatarAllowed() && remotePicture()} fallback={
                          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                          </svg>
                        }>
                          <button
                            type="button"
                            class="notification-avatar-load"
                            aria-label="Load avatar from the inviter's profile"
                            title="Not loaded: this picture is hosted wherever the inviter chose. Click to load it."
                            onClick={(e) => { e.stopPropagation(); requestAvatar(inv.invitationId); }}
                          >
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                              <rect x="3" y="3" width="18" height="18" rx="2"></rect>
                              <circle cx="8.5" cy="8.5" r="1.5"></circle>
                              <polyline points="21 15 16 10 5 21"></polyline>
                            </svg>
                          </button>
                        </Show>
                      }>
                        <img src={avatarSrc()} alt="" class="notification-avatar-img" />
                      </Show>
                    </div>
                    <div class="notification-content">
                      <div class="notification-sender">
                        {ownerProfile()?.name || formatPubkey(inv.owner, 8)}
                      </div>
                      <div class="notification-fingerprint">
                        <KeyFingerprint pubkey={inv.owner} />
                      </div>
                      <div class="notification-title">
                        Shared vault {shortVaultId(inv.vaultId)}
                        <span class={`vault-badge vault-badge--${inv.cap === 'write' ? 'writer' : 'reader'}`}>
                          {inv.cap === 'write' ? 'write' : 'read'}
                        </span>
                        <Show when={inv.accepted}>
                          <span class="vault-badge vault-badge--ok">accepted</span>
                        </Show>
                      </div>
                    </div>
                    <div class="notification-arrow">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6"></polyline>
                      </svg>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>

        <Show when={props.sharedDocuments.length > 0}>
          <Show when={showGroups()}>
            <div class="notifications-group-title">Document snapshots</div>
          </Show>
          <div class="notifications-list">
            <For each={props.sharedDocuments}>
              {(doc) => {
                const profile = () => getSenderProfile(doc);
                const displayName = () => getDisplayName(doc);
                
                return (
                  <div 
                    class={`notification-item ${doc.isRead ? 'read' : 'unread'}`}
                    onClick={() => props.onPreview(doc)}
                  >
                    <div class="notification-unread-dot">
                      <Show when={!doc.isRead}>
                        <span></span>
                      </Show>
                    </div>
                    <div class="notification-avatar">
                      <Show when={sanitizeImageUrl(profile().picture)} fallback={
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                          <circle cx="12" cy="7" r="4"></circle>
                        </svg>
                      }>
                        <img src={sanitizeImageUrl(profile().picture)} alt="" class="notification-avatar-img" />
                      </Show>
                    </div>
                    <div class="notification-content">
                      <div class="notification-sender">
                        {profile().name || formatPubkey(doc.senderPubkey, 8)}
                      </div>
                      <div class="notification-title">{displayName()}</div>
                      <div class="notification-time">{formatTimeAgo(doc.createdAt)}</div>
                    </div>
                    <div class="notification-arrow">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6"></polyline>
                      </svg>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
};

export default NotificationsPanel;
