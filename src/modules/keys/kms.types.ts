/**
 * Key Management Service abstraction.
 *
 * JWT signing keys and data-encryption keys are ALWAYS accessed through
 * this interface - never read from source code or config directly.
 *
 * Implementations:
 *  - LocalKeyProvider  : local development / small deployments (keys wrapped
 *                        at rest with a master key)
 *  - AwsKmsProvider    : future (AWS KMS)
 *  - AzureKvProvider   : future (Azure Key Vault)
 *  - GcpKmsProvider    : future (Google Cloud KMS)
 *  - VaultProvider     : future (HashiCorp Vault / HSM)
 *
 * SECURITY DECISION: Ed25519 (EdDSA) is used for signing - smaller keys and
 * signatures than RSA/ECDSA at equivalent security, fast verification.
 */
export interface SigningPublicKey {
  kid: string;
  algorithm: 'EdDSA';
  /** SPKI PEM encoding. */
  publicKeyPem: string;
  createdAt: Date;
}

/** Envelope produced by the data-encryption functions (e.g. MFA secrets). */
export interface EncryptedEnvelope {
  v: number;
  iv: string;
  ct: string;
  tag: string;
}

export interface KeyManagementService {
  /**
   * Returns the current signing key material (private). Only the token
   * service may call this; callers never see raw PEM outside the process.
   */
  getCurrentSigningKey(): Promise<{
    kid: string;
    privateKeyPem: string;
    publicKeyPem: string;
  }>;

  getPublicKey(kid: string): Promise<SigningPublicKey>;
  listPublicKeys(): Promise<SigningPublicKey[]>;

  /** Generates and persists a NEW current signing key (key rotation). Old keys remain for verification. */
  rotateSigningKey(): Promise<{ kid: string }>;

  /** Authenticated encryption of small sensitive blobs (MFA TOTP secrets). */
  encrypt(plaintext: Buffer): Promise<EncryptedEnvelope>;
  decrypt(envelope: EncryptedEnvelope): Promise<Buffer>;
}

export class KmsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KmsError';
  }
}
