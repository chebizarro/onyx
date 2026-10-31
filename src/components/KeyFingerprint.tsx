/**
 * KeyFingerprint
 *
 * A stable, human-comparable fingerprint for a Nostr public key. Profile
 * names and avatars are attacker-controlled and freely copyable; the key is
 * not. The fingerprint is always rendered next to a display name so that two
 * people can compare it over another channel. No emoji: the visual hash is
 * four words from a fixed 256-word list, derived from SHA-256 of the key.
 */

import { Component, createMemo } from 'solid-js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

export interface KeyFingerprintParts {
  /** First and last eight hex characters of the key, e.g. `0123abcd...89effedc`. */
  readonly hex: string;
  /** Four words (32 bits) from `FINGERPRINT_WORDS`, space separated. */
  readonly words: string;
}

/** 256 short, concrete, visually distinct words; index = one byte of the hash. */
export const FINGERPRINT_WORDS: readonly string[] = Object.freeze([
  'acorn', 'amber', 'anchor', 'anvil', 'apple', 'apron', 'arrow', 'aspen', 'atlas', 'attic', 'badge', 'bagel', 'banjo', 'barn', 'basil', 'beach',
  'beacon', 'bell', 'bench', 'berry', 'birch', 'bison', 'blade', 'board', 'boat', 'bolt', 'book', 'boot', 'bottle', 'bow', 'box', 'brick',
  'bridge', 'broom', 'brush', 'bucket', 'bugle', 'button', 'cabin', 'cable', 'cactus', 'camel', 'candle', 'canoe', 'canvas', 'cargo', 'carrot', 'castle',
  'cedar', 'cello', 'chain', 'chair', 'chalk', 'cherry', 'chess', 'chimney', 'cider', 'circle', 'clock', 'cloud', 'clover', 'coal', 'cobalt', 'coin',
  'comet', 'compass', 'coral', 'cotton', 'crane', 'crow', 'crystal', 'cup', 'daisy', 'deer', 'delta', 'desk', 'diamond', 'dime', 'dollar', 'dome',
  'door', 'dragon', 'drum', 'eagle', 'earth', 'easel', 'echo', 'eel', 'elm', 'ember', 'engine', 'falcon', 'feather', 'fern', 'fiddle', 'field',
  'flag', 'flame', 'flute', 'forest', 'fossil', 'fox', 'frame', 'frost', 'garden', 'garlic', 'gate', 'gear', 'ginger', 'glass', 'globe', 'glove',
  'goat', 'goose', 'grape', 'gravel', 'guitar', 'hammer', 'harbor', 'harp', 'hawk', 'hazel', 'heron', 'hill', 'honey', 'horse', 'hound', 'igloo',
  'ink', 'iris', 'iron', 'island', 'ivory', 'jacket', 'jade', 'jaguar', 'jar', 'jelly', 'jewel', 'juniper', 'kayak', 'kettle', 'key', 'kite',
  'knot', 'ladder', 'lake', 'lamp', 'lantern', 'laser', 'leaf', 'lemon', 'lens', 'lily', 'lime', 'lion', 'lizard', 'lobster', 'lotus', 'magnet',
  'mango', 'maple', 'marble', 'mask', 'meadow', 'melon', 'metal', 'mirror', 'moon', 'moss', 'moth', 'mountain', 'mouse', 'mule', 'needle', 'nest',
  'nickel', 'noodle', 'north', 'nutmeg', 'oak', 'oasis', 'ocean', 'olive', 'onion', 'opal', 'orange', 'orbit', 'orchid', 'otter', 'oven', 'oyster',
  'paddle', 'palm', 'panda', 'paper', 'parrot', 'peach', 'pearl', 'pebble', 'pencil', 'penguin', 'pepper', 'piano', 'pillow', 'pine', 'planet', 'plum',
  'pocket', 'pond', 'poppy', 'prism', 'pumpkin', 'puzzle', 'quail', 'quartz', 'quill', 'rabbit', 'radar', 'radio', 'raven', 'reef', 'ribbon', 'river',
  'robin', 'rocket', 'rose', 'ruby', 'rudder', 'saddle', 'salmon', 'sand', 'satin', 'scarf', 'shell', 'ship', 'silk', 'silver', 'sketch', 'snail',
  'snow', 'sofa', 'spoon', 'spruce', 'squid', 'stamp', 'star', 'stone', 'storm', 'sugar', 'summit', 'sunset', 'swan', 'table', 'tiger', 'timber',
]);

/** Deterministic fingerprint for a hex public key (case-insensitive). */
export function keyFingerprint(pubkey: string): KeyFingerprintParts {
  const hex = pubkey.trim().toLowerCase();
  const digest = sha256(utf8ToBytes(hex));
  const words = Array.from(digest.subarray(0, 4), (byte) => FINGERPRINT_WORDS[byte]).join(' ');
  const bookends = hex.length > 16 ? `${hex.slice(0, 8)}...${hex.slice(-8)}` : hex;
  return { hex: bookends, words };
}

export interface KeyFingerprintProps {
  pubkey: string;
  class?: string;
}

const KeyFingerprint: Component<KeyFingerprintProps> = (props) => {
  const parts = createMemo(() => keyFingerprint(props.pubkey));
  return (
    <span
      class={`vault-fingerprint ${props.class ?? ''}`.trim()}
      data-testid="key-fingerprint"
      title={`Key fingerprint. Compare it with the other person over a channel you trust. Full key: ${props.pubkey}`}
    >
      <code class="vault-fingerprint__hex">{parts().hex}</code>
      <span class="vault-fingerprint__words">{parts().words}</span>
    </span>
  );
};

export default KeyFingerprint;
