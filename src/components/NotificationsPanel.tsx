/**
 * NotificationsPanel Component
 * 
 * Shows documents shared with the current user.
 * Displays sender info, document title, and allows preview/import.
 */

import { Component, For, Show, createSignal, createEffect } from 'solid-js';
import { formatPubkey } from '../lib/nostr/nip05';
import { fetchUserProfile } from '../lib/nostr/login';
import { getSyncEngine } from '../lib/nostr/sync';
import { sanitizeImageUrl } from '../lib/security';
import type { SharedDocument, NostrProfile } from '../lib/nostr/types';

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
}

const NotificationsPanel: Component<NotificationsPanelProps> = (props) => {
  const unreadCount = () => props.sharedDocuments.filter(d => !d.isRead).length;

  // Cache of fetched sender profiles (pubkey -> profile)
  const [senderProfiles, setSenderProfiles] = createSignal<Map<string, NostrProfile>>(new Map());
  const [fetchingProfiles, setFetchingProfiles] = createSignal<Set<string>>(new Set());

  // Failed and empty lookups are terminal for this panel, just like successful ones.
  const attemptedProfiles = new Set<string>();

  // Fetch profiles for all unique senders
  createEffect(() => {
    const docs = props.sharedDocuments;
    const profiles = senderProfiles();
    const fetching = fetchingProfiles();
    
    // Get unique sender pubkeys we haven't fetched yet
    const pubkeysToFetch = [...new Set(docs.map(d => d.senderPubkey))]
      .filter(pk => !attemptedProfiles.has(pk) && !profiles.has(pk) && !fetching.has(pk));
    
    if (pubkeysToFetch.length === 0) return;
    
    pubkeysToFetch.forEach(pk => attemptedProfiles.add(pk));

    // Mark as fetching
    setFetchingProfiles(prev => {
      const next = new Set(prev);
      pubkeysToFetch.forEach(pk => next.add(pk));
      return next;
    });
    
    // Fetch profiles concurrently
    const engine = getSyncEngine();
    const relays = engine.getConfig().relays;
    
    pubkeysToFetch.forEach(async (pubkey) => {
      try {
        const profile = await fetchUserProfile(pubkey, relays);
        if (profile) {
          setSenderProfiles(prev => {
            const next = new Map(prev);
            next.set(pubkey, {
              pubkey,
              name: profile.displayName || profile.name,
              picture: profile.picture,
              nip05: profile.nip05,
            });
            return next;
          });
        }
      } catch (err) {
        console.error('Failed to fetch sender profile:', err);
      } finally {
        setFetchingProfiles(prev => {
          const next = new Set(prev);
          next.delete(pubkey);
          return next;
        });
      }
    });
  });

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
        <Show when={props.isLoading && props.sharedDocuments.length === 0}>
          <div class="notifications-loading">
            <div class="spinner"></div>
            <span>Loading shared documents...</span>
          </div>
        </Show>

        <Show when={!props.isLoading && props.sharedDocuments.length === 0}>
          <div class="notifications-empty">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
            </svg>
            <p>No documents shared with you yet</p>
            <span>When someone shares a document, it will appear here</span>
          </div>
        </Show>

        <Show when={props.sharedDocuments.length > 0}>
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
