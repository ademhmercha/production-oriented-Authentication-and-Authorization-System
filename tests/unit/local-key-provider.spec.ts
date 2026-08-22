import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalKeyProvider } from '../../src/modules/keys/local-key-provider';
import { KmsError } from '../../src/modules/keys/kms.types';

function makeProvider(masterKeyB64?: string): { provider: LocalKeyProvider; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kms-test-'));
  if (masterKeyB64 !== undefined) {
    process.env.KMS_MASTER_KEY = masterKeyB64;
  }
  return { provider: new LocalKeyProvider(dir), dir };
}

describe('LocalKeyProvider', () => {
  afterEach(() => {
    process.env.KMS_MASTER_KEY = Buffer.alloc(32, 0xab).toString('base64');
  });

  it('generates a signing key on first use and exposes its public key', async () => {
    const { provider } = makeProvider();
    const current = await provider.getCurrentSigningKey();
    expect(current.kid).toMatch(/^sig-/);
    expect(current.privateKeyPem).toContain('PRIVATE KEY');
    const keys = await provider.listPublicKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]!.publicKeyPem).toContain('PUBLIC KEY');
  });

  it('wraps private keys at rest (no plaintext PEM in key files)', async () => {
    const { provider, dir } = makeProvider();
    const { kid } = await provider.rotateSigningKey();
    const raw = readFileSync(join(dir, `signing-${kid}.json`), 'utf8');
    expect(raw).not.toContain('PRIVATE KEY');
    const parsed = JSON.parse(raw);
    expect(parsed.wrappedPrivateKey.split('.')).toHaveLength(4);
  });

  it('rotation adds a new current key while keeping the old one for verification', async () => {
    const { provider } = makeProvider();
    const first = await provider.getCurrentSigningKey();
    const second = await provider.rotateSigningKey();
    expect(second.kid).not.toBe(first.kid);

    const nowCurrent = await provider.getCurrentSigningKey();
    expect(nowCurrent.kid).toBe(second.kid);
    const all = await provider.listPublicKeys();
    expect(all.map((k) => k.kid)).toContain(first.kid);
    // old key still retrievable by kid
    await expect(provider.getPublicKey(first.kid)).resolves.toMatchObject({ kid: first.kid });
  });

  it('encrypt/decrypt roundtrip', async () => {
    const { provider } = makeProvider();
    const plaintext = Buffer.from('totp-secret-JBSWY3DPEHPK3PXP');
    const envelope = await provider.encrypt(plaintext);
    const decrypted = await provider.decrypt(envelope);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it('detects tampered ciphertext', async () => {
    const { provider } = makeProvider();
    const envelope = await provider.encrypt(Buffer.from('secret'));
    envelope.ct = Buffer.from('tampered-data!!').toString('base64');
    await expect(provider.decrypt(envelope)).rejects.toBeInstanceOf(KmsError);
  });

  it('fails decryption with a different master key', async () => {
    const dirA = mkdtempSync(join(tmpdir(), 'kms-test-'));
    process.env.KMS_MASTER_KEY = Buffer.alloc(32, 1).toString('base64');
    const providerA = new LocalKeyProvider(dirA);
    const envelope = await providerA.encrypt(Buffer.from('secret'));

    process.env.KMS_MASTER_KEY = Buffer.alloc(32, 2).toString('base64');
    const dirB = mkdtempSync(join(tmpdir(), 'kms-test-'));
    writeFileSync(join(dirB, 'master.key'), Buffer.alloc(32, 2).toString('base64'));
    const providerB = new LocalKeyProvider(dirB);
    await expect(providerB.decrypt(envelope)).rejects.toBeInstanceOf(KmsError);
  });

  it('rejects traversal-style kids when reading keys', async () => {
    const { provider } = makeProvider();
    await expect(provider.getPublicKey('../../etc/passwd')).rejects.toBeInstanceOf(KmsError);
    void rmSync;
  });
});
