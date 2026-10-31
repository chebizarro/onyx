import { beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultError } from '../errors';
import type { VaultEngine, VaultEngineDeps } from '../engine-api';

function engine(): VaultEngine {
  const done = async () => {};
  return {
    deviceKeys: { getState: vi.fn(), setEnabled: vi.fn(), generate: vi.fn(), import: vi.fn(), announce: vi.fn(), useIdentityFallback: vi.fn(),
      observeRecipient: vi.fn(), approveRecipientKey: vi.fn(), resetRecipientPin: vi.fn() },
    start: done, stop: vi.fn(done), subscribe: () => () => {},
    updateNetworkDefaults: done,
    create: vi.fn<VaultEngine['create']>(),
    share: done, attach: vi.fn<VaultEngine['attach']>(), takeOverPublishing: done,
    accept: vi.fn<VaultEngine['accept']>(), sync: done, revoke: done,
    resolveConflicts: done, reseal: done, pause: done, resume: done, detach: done,
    notifyFilesChanged: () => {}, refreshInbox: done, repairInbox: done,
    exportRecovery: vi.fn<VaultEngine['exportRecovery']>(),
  };
}

beforeEach(() => vi.resetModules());

describe('vault engine registry', () => {
  it('fails closed until registered', async () => {
    const api = await import('../engine-api');
    const { VaultError } = await import('../errors');
    expect(() => api.getVaultEngine()).toThrow(VaultError);
    expect(() => api.getVaultEngine()).toThrow('engine not registered');
    try { api.getVaultEngine(); } catch (error) {
      expect(error).toMatchObject({ code: 'UNSUPPORTED', retryable: false });
    }
    await api.resetVaultEngine();
    expect(() => api.getVaultEngine()).toThrow('engine not registered');
  });

  it('lazily constructs one instance and forwards dependencies', async () => {
    const api = await import('../engine-api');
    const value = engine();
    const factory = vi.fn(() => value);
    const deps: VaultEngineDeps = { clock: () => 123 };
    api.registerVaultEngineFactory(factory);
    expect(factory).not.toHaveBeenCalled();
    expect(api.getVaultEngine(deps)).toBe(value);
    expect(api.getVaultEngine()).toBe(value);
    expect(factory).toHaveBeenCalledExactlyOnceWith(deps);
  });

  it('awaits stop before discarding the instance and retains registration', async () => {
    const api = await import('../engine-api');
    const first = engine();
    const second = engine();
    let release!: () => void;
    first.stop = vi.fn(() => new Promise<void>(resolve => { release = resolve; }));
    const factory = vi.fn().mockReturnValueOnce(first).mockReturnValueOnce(second);
    api.registerVaultEngineFactory(factory);
    expect(api.getVaultEngine()).toBe(first);
    let resetDone = false;
    const reset = api.resetVaultEngine().then(() => { resetDone = true; });
    await Promise.resolve();
    expect(resetDone).toBe(false);
    expect(api.getVaultEngine()).toBe(first);
    release();
    await reset;
    expect(first.stop).toHaveBeenCalledOnce();
    expect(api.getVaultEngine()).toBe(second);
    await api.resetVaultEngine();
    await api.resetVaultEngine();
    expect(second.stop).toHaveBeenCalledOnce();
  });

  it('does not instantiate an engine on reset', async () => {
    const api = await import('../engine-api');
    const factory = vi.fn(() => engine());
    api.registerVaultEngineFactory(factory);
    await api.resetVaultEngine();
    expect(factory).not.toHaveBeenCalled();
  });

  it('preserves an instance when stop fails', async () => {
    const api = await import('../engine-api');
    const value = engine();
    const failure = new VaultError('IO', { operation: 'stop' });
    value.stop = vi.fn().mockRejectedValue(failure);
    api.registerVaultEngineFactory(() => value);
    api.getVaultEngine();
    await expect(api.resetVaultEngine()).rejects.toBe(failure);
    expect(api.getVaultEngine()).toBe(value);
  });

  it('uses a replacement factory only after stopping the current instance', async () => {
    const api = await import('../engine-api');
    const first = engine();
    const second = engine();
    api.registerVaultEngineFactory(() => first);
    api.getVaultEngine();
    const replacement = vi.fn(() => second);
    api.registerVaultEngineFactory(replacement);
    expect(api.getVaultEngine()).toBe(first);
    expect(replacement).not.toHaveBeenCalled();
    await api.resetVaultEngine();
    expect(first.stop).toHaveBeenCalledOnce();
    expect(api.getVaultEngine()).toBe(second);
  });

  it('allows retry after a factory throws', async () => {
    const api = await import('../engine-api');
    const value = engine();
    const factory = vi.fn().mockImplementationOnce(() => { throw new VaultError('STORAGE'); })
      .mockReturnValue(value);
    api.registerVaultEngineFactory(factory);
    expect(() => api.getVaultEngine()).toThrow(VaultError);
    expect(api.getVaultEngine()).toBe(value);
  });
});
