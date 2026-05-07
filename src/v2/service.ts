import AesEncryption from "../helpers/aes.js";
import BrantaPaymentException from "../classes/brantaPaymentException.js";
import BrantaClientOptions from "../classes/brantaClientOptions.js";
import { IBrantaClient, IBrantaService, Payment, ZKPaymentResult } from "./types.js";
import { BrantaClient } from "./client.js";

export class BrantaService implements IBrantaService {
  private readonly _client: IBrantaClient;
  private readonly _defaultOptions: BrantaClientOptions;

  constructor(defaultOptions: BrantaClientOptions, client?: IBrantaClient) {
    this._defaultOptions = defaultOptions;
    this._client = client ?? new BrantaClient(defaultOptions);
  }

  async getPayments(address: string, destinationEncryptionKey: string | null = null, options: BrantaClientOptions | null = null): Promise<Payment[]> {
    if (!destinationEncryptionKey) {
      const privacy = options?.privacy ?? this._defaultOptions?.privacy;
      if (privacy === 'strict') {
        throw new BrantaPaymentException("privacy is set to 'strict': plain on-chain address lookups are not permitted");
      }
    }

    const payments = await this._client.getPayments(address, options);
    const baseUrl = this._resolveBaseUrl(options);

    if (destinationEncryptionKey) {
      for (const payment of payments) {
        for (const destination of payment?.destinations || []) {
          if (destination.zk === false) continue;
          destination.value = await AesEncryption.decrypt(destination.value, destinationEncryptionKey);
        }
        payment.verifyUrl = this._buildVerifyUrl(baseUrl, address, destinationEncryptionKey);
      }
    } else {
      for (const payment of payments) {
        payment.verifyUrl = this._buildVerifyUrl(baseUrl, address);
      }
    }

    return payments;
  }

  async addPayment(payment: Payment, options: BrantaClientOptions | null = null): Promise<ZKPaymentResult> {
    const secret = crypto.randomUUID();
    let hasZk = false;

    for (const destination of payment?.destinations || []) {
      if (destination.zk !== true) continue;
      hasZk = true;
      destination.value = await AesEncryption.encrypt(destination.value, secret);
    }

    const baseUrl = this._resolveBaseUrl(options);
    const paymentResponse = await this._client.postPayment(payment, options);
    const firstValue = payment.destinations[0].value;

    if (hasZk) {
      paymentResponse.verifyUrl = this._buildVerifyUrl(baseUrl, firstValue, secret);
      const verifyLink = `${baseUrl}/v2/zk-verify/${encodeURIComponent(firstValue)}#secret=${secret}`;
      return { payment: paymentResponse, verifyLink, secret };
    }

    paymentResponse.verifyUrl = this._buildVerifyUrl(baseUrl, firstValue);
    const verifyLink = `${baseUrl}/v2/verify/${encodeURIComponent(firstValue)}`;
    return { payment: paymentResponse, verifyLink, secret };
  }

  async getPaymentsByQRCode(qrText: string, options: BrantaClientOptions | null = null): Promise<Payment[]> {
    const text = qrText.trim();

    let url: URL | null = null;
    try { url = new URL(text); } catch { /* not a URL */ }

    if (!url) return this._getPlainPayments(this._normalizeAddress(text), options);

    const rawParams = new URLSearchParams(url.search.replace(/\+/g, '%2B'));
    const brantaId = rawParams.get('branta_id');
    const brantaSecret = rawParams.get('branta_secret');
    if (brantaId && brantaSecret) return this.getPayments(brantaId, brantaSecret, options);

    if (url.protocol === 'bitcoin:') {
      return this._getPlainPayments(this._normalizeAddress(url.pathname), options);
    }

    if (url.protocol === 'http:' || url.protocol === 'https:') {
      const baseUrl = this._resolveBaseUrl(options);
      if (!baseUrl || new URL(baseUrl).origin !== url.origin) {
        return this._getPlainPayments(this._normalizeAddress(text), options);
      }

      const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      const [version, type, id] = segments;

      if (version === 'v2' && id) {
        if (type === 'verify') return this._getPlainPayments(id, options);
        if (type === 'zk-verify') {
          const secret = new URLSearchParams(url.hash.slice(1)).get('secret');
          if (secret) return this.getPayments(id, secret, options);
          return this._getPlainPayments(id, options);
        }
      }

      const lastSegment = segments.at(-1);
      if (lastSegment) return this._getPlainPayments(lastSegment, options);
    }

    return this._getPlainPayments(this._normalizeAddress(text), options);
  }

  async isApiKeyValid(options: BrantaClientOptions | null = null): Promise<boolean> {
    return this._client.isApiKeyValid(options);
  }

  private _getPlainPayments(address: string, options: BrantaClientOptions | null): Promise<Payment[]> {
    const privacy = options?.privacy ?? this._defaultOptions?.privacy;
    if (privacy === 'strict') return Promise.resolve([]);
    return this.getPayments(address, null, options);
  }

  private _buildVerifyUrl(baseUrl: string, address: string, secret?: string): string {
    const encoded = encodeURIComponent(address);
    if (secret) {
      return `${baseUrl}/v2/zk-verify/${encoded}#secret=${secret}`;
    }
    return `${baseUrl}/v2/verify/${encoded}`;
  }

  private _resolveBaseUrl(options: BrantaClientOptions | null): string {
    const baseUrl = options?.baseUrl ?? this._defaultOptions?.baseUrl;
    return typeof baseUrl === 'string' ? baseUrl : baseUrl?.url ?? '';
  }

  private _normalizeAddress(text: string): string {
    const lower = text.toLowerCase();
    if (lower.startsWith('lightning:')) return lower.slice('lightning:'.length);
    if (lower.startsWith('bitcoin:')) {
      const addr = text.slice('bitcoin:'.length);
      const addrLower = addr.toLowerCase();
      return addrLower.startsWith('bc1q') || addrLower.startsWith('bcrt') ? addrLower : addr;
    }
    if (lower.startsWith('lnbc') || lower.startsWith('bc1q')) return lower;
    return text;
  }
}

export default BrantaService;
