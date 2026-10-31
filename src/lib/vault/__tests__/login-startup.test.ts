import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getPublicKey, nip19 } from 'nostr-tools';

const mocks = vi.hoisted(() => ({ get: vi.fn(), authenticate: vi.fn(), mobile: false }));
vi.mock('@platform', () => ({ platform: { secrets: { get: mocks.get } } }));
vi.mock('../../biometric', () => ({ authenticateWithBiometric: mocks.authenticate }));
vi.mock('../../platform', () => ({ isMobile: () => mocks.mobile }));
import { getCurrentLoginWithAuth } from '../../nostr/login';
import { createSignerFromLogin } from '../../nostr/signer';

beforeEach(() => { vi.clearAllMocks(); mocks.mobile = false; });
describe('shared-vault authenticated login', () => {
  it.each([false, true])('loads a signer from the same unlocked login (mobile=%s)', async mobile => {
    mocks.mobile = mobile; mocks.authenticate.mockResolvedValue(true);
    const key = new Uint8Array(32).fill(17);
    const login = { id: 'throwaway', type: 'nsec', pubkey: getPublicKey(key), nsec: nip19.nsecEncode(key) };
    mocks.get.mockResolvedValue(JSON.stringify(login));
    const unlocked = await getCurrentLoginWithAuth();
    expect(unlocked).not.toBeNull();
    expect(await createSignerFromLogin(unlocked!)!.getPublicKey()).toBe(login.pubkey);
    expect(mocks.get).toHaveBeenCalledOnce();
    expect(mocks.authenticate).toHaveBeenCalledTimes(mobile ? 1 : 0);
  });

  it('does not read credentials after biometric cancellation', async () => {
    mocks.mobile = true; mocks.authenticate.mockResolvedValue(false);
    expect(await getCurrentLoginWithAuth()).toBeNull();
    expect(mocks.get).not.toHaveBeenCalled();
  });

  it('returns no login when the OS secret store refuses access, rather than inventing a signer', async () => {
    mocks.get.mockRejectedValue(new Error('secret store locked'));
    expect(await getCurrentLoginWithAuth()).toBeNull();
  });
});
