import {
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  EncryptedEnvelope,
  KeyManagementService,
  KmsError,
  SigningPublicKey,
} from './kms.types';

interface WrappedSigningKeyFile {
  kid: string;
  alg: 'EdDSA';
  createdAt: string;
  publicKeyPem: string;
  /** AES-256-GCM wrapped PKCS8 private key: v1|iv|ct|tag (base64 parts). */
  wrappedPrivateKey: string;
}

const ENVELOPE_VERSION = 1;

/**
 * Local development key provider.
 *
 * - Ed25519 signing keys are generated locally and stored in KMS_KEY_DIR.
 * - Private keys are WRAPPED (AES-256-GCM) with a master key before hitting
 *   disk; plaintext keys never touch the filesystem.
 * - The master key comes from KMS_MASTER_KEY (base64). In development it may
 *   be auto-generated into <KMS_KEY_DIR>/master.key (gitignored). Production
 *   MUST supply KMS_MASTER_KEY from a secret manager.
 * - kid values enable rotation: rotateSigningKey() adds a new key; old keys
 *   remain listed for JWKS verification until tokens expire naturally.
 */
export class LocalKeyProvider implements KeyManagementService {
  private readonly keyDir: string;
  private masterKeyCache?: Buffer;
  private rotateSeq = 0;

  constructor(keyDir: string) {
    this.keyDir = keyDir;
    if (!existsSync(this.keyDir)) {
      mkdirSync(this.keyDir, { recursive: true });
    }
  }

  // Master / data-encryption key

  private masterKey(): Buffer {
    if (this.masterKeyCache) return this.masterKeyCache;

    const fromEnv = process.env.KMS_MASTER_KEY;
    if (fromEnv && fromEnv.trim() !== '') {
      const buf = Buffer.from(fromEnv, 'base64');
      if (buf.length !== 32) throw new KmsError('KMS_MASTER_KEY must be 32 bytes base64');
      this.masterKeyCache = buf;
      return buf;
    }

    if (process.env.NODE_ENV === 'production') {
      throw new KmsError('KMS_MASTER_KEY is required in production');
    }

    // Development convenience: persist a random master key under keys/ (gitignored).
    const masterFile = join(this.keyDir, 'master.key');
    if (!existsSync(masterFile)) {
      writeFileSync(masterFile, randomBytes(32).toString('base64'), { mode: 0o600 });
    }
    this.masterKeyCache = Buffer.from(readFileSync(masterFile, 'utf8').trim(), 'base64');
    return this.masterKeyCache!;
  }

  /** Derives the symmetric data-protection key via HKDF (domain separated). */
  private dataEncryptionKey(): Buffer {
    const derived = hkdfSync(
      'sha256',
      this.masterKey(),
      new Uint8Array(0),
      Buffer.from('identity-platform:data-encryption:v1'),
      32,
    );
    return Buffer.from(derived);
  }

  // Envelope encryption

  async encrypt(plaintext: Buffer): Promise<EncryptedEnvelope> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.dataEncryptionKey(), iv);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      v: ENVELOPE_VERSION,
      iv: iv.toString('base64'),
      ct: ct.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };
  }

  async decrypt(envelope: EncryptedEnvelope): Promise<Buffer> {
    if (envelope.v !== ENVELOPE_VERSION) throw new KmsError(`Unsupported envelope version ${envelope.v}`);
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.dataEncryptionKey(),
        Buffer.from(envelope.iv, 'base64'),
      );
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(envelope.ct, 'base64')),
        decipher.final(),
      ]);
    } catch {
      throw new KmsError('Decryption failed - data tampered or wrong master key');
    }
  }

  // Signing keys

  private wrapPrivateKey(privateKeyPem: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.masterKey(), iv);
    const ct = Buffer.concat([cipher.update(privateKeyPem, 'utf8'), cipher.final()]);
    return [
      String(ENVELOPE_VERSION),
      iv.toString('base64'),
      ct.toString('base64'),
      cipher.getAuthTag().toString('base64'),
    ].join('.');
  }

  private unwrapPrivateKey(wrapped: string): string {
    const [v, ivB64, ctB64, tagB64] = wrapped.split('.');
    if (v !== String(ENVELOPE_VERSION)) throw new KmsError('Unsupported wrapped key version');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.masterKey(),
      Buffer.from(ivB64, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(ctB64, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  }

  private keyFilePath(kid: string): string {
    // kid format is controlled by us; still guard against traversal.
    if (!/^[A-Za-z0-9._-]+$/.test(kid)) throw new KmsError('Invalid kid');
    return join(this.keyDir, `signing-${kid}.json`);
  }

  listSigningKeyFiles(): WrappedSigningKeyFile[] {
    return readdirSync(this.keyDir)
      .filter((f) => f.startsWith('signing-') && f.endsWith('.json'))
      .map((f) => JSON.parse(readFileSync(join(this.keyDir, f), 'utf8')) as WrappedSigningKeyFile)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.kid.localeCompare(a.kid));
  }

  async getCurrentSigningKey(): Promise<{ kid: string; privateKeyPem: string; publicKeyPem: string }> {
    const files = this.listSigningKeyFiles();
    if (files.length === 0) {
      await this.rotateSigningKey();
      return this.getCurrentSigningKey();
    }
    const current = files[0];
    if (!current) throw new KmsError('No signing key available');
    return {
      kid: current.kid,
      privateKeyPem: this.unwrapPrivateKey(current.wrappedPrivateKey),
      publicKeyPem: current.publicKeyPem,
    };
  }

  async getPublicKey(kid: string): Promise<SigningPublicKey> {
    const file = this.listSigningKeyFiles().find((f) => f.kid === kid);
    if (!file) throw new KmsError(`Unknown signing key: ${kid}`);
    return {
      kid: file.kid,
      algorithm: 'EdDSA',
      publicKeyPem: file.publicKeyPem,
      createdAt: new Date(file.createdAt),
    };
  }

  async listPublicKeys(): Promise<SigningPublicKey[]> {
    return this.listSigningKeyFiles()
      .map((f) => ({
        kid: f.kid,
        algorithm: 'EdDSA' as const,
        publicKeyPem: f.publicKeyPem,
        createdAt: new Date(f.createdAt),
      }))
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || b.kid.localeCompare(a.kid));
  }

  async rotateSigningKey(): Promise<{ kid: string }> {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

    const fingerprint = createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 8);
    const kid = `sig-${new Date().toISOString().slice(0, 10)}-${fingerprint}-${randomBytes(2)
      .toString('hex')}`;

    const file: WrappedSigningKeyFile = {
      kid,
      alg: 'EdDSA',
      createdAt: new Date(Date.now() + this.rotateSeq++).toISOString(),
      publicKeyPem,
      wrappedPrivateKey: this.wrapPrivateKey(privateKeyPem),
    };
    writeFileSync(this.keyFilePath(kid), JSON.stringify(file, null, 2), { mode: 0o600 });
    return { kid };
  }
}
