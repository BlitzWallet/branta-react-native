import AesEncryption from "../helpers/aes.js";
import { getHashZkType, toNormalizedHash } from "../helpers/hashZk.js";
import BrantaPaymentException from "../classes/brantaPaymentException.js";
import BrantaClientOptions from "../classes/brantaClientOptions.js";
import {
  IBrantaClient,
  IBrantaService,
  Destination,
  DestinationType,
  Payment,
  ZKPaymentResult,
} from "./types.js";
import { BrantaClient } from "./client.js";
import { randomBytes } from "@noble/hashes/utils.js";

function generateUUID(): string {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export class BrantaService implements IBrantaService {
  private readonly _client: IBrantaClient;
  private readonly _defaultOptions: BrantaClientOptions;

  constructor(defaultOptions: BrantaClientOptions, client?: IBrantaClient) {
    this._defaultOptions = defaultOptions;
    this._client = client ?? new BrantaClient(defaultOptions);
  }

  async getPayments(
    address: string,
    destinationEncryptionKey: string | null = null,
    options: BrantaClientOptions | null = null,
  ): Promise<Payment[]> {
    const hashZkType = getHashZkType(address);

    if (!hashZkType && !destinationEncryptionKey) {
      const privacy = options?.privacy ?? this._defaultOptions?.privacy;
      if (privacy === "strict") {
        throw new BrantaPaymentException(
          "privacy is set to 'strict': plain on-chain address lookups are not permitted",
        );
      }
    }

    let lookupValue = address;
    if (hashZkType) {
      const hash = await toNormalizedHash(address);
      lookupValue = await AesEncryption.encrypt(address, hash, true);
    }

    let payments = await this._client.getPayments(lookupValue, options);

    if (payments.length === 0 && hashZkType) {
      const privacy = options?.privacy ?? this._defaultOptions?.privacy;
      if (privacy !== "strict") {
        lookupValue = address;
        payments = await this._client.getPayments(address, options);
      }
    }

    const baseUrl = this._resolveBaseUrl(options);
    for (const payment of payments) {
      const keys = await this._decryptDestinations(
        payment.destinations,
        address,
        destinationEncryptionKey,
        hashZkType,
      );
      payment.verifyUrl = this._buildVerifyUrl(baseUrl, lookupValue, keys);
    }

    return payments;
  }

  async addPayment(
    payment: Payment,
    options: BrantaClientOptions | null = null,
  ): Promise<ZKPaymentResult> {
    const privacy = options?.privacy ?? this._defaultOptions?.privacy;
    if (privacy === "strict" && payment.destinations.some((d) => !d.zk)) {
      throw new BrantaPaymentException(
        "privacy is set to 'strict': all destinations must have zk enabled",
      );
    }

    const secret = generateUUID();
    const encryptedToKey = new Map<string, string>();

    for (const dest of payment.destinations) {
      if (!dest.zk) continue;

      if (dest.type === "bitcoin_address") {
        dest.value = await AesEncryption.encrypt(dest.value, secret, false);
        encryptedToKey.set(dest.value, secret);
      } else {
        const hashZkType = getHashZkType(dest.value);
        if (!hashZkType) {
          throw new BrantaPaymentException(
            `destination type '${dest.type}' does not support ZK`,
          );
        }
        const hash = await toNormalizedHash(dest.value);
        dest.value = await AesEncryption.encrypt(dest.value, hash, true);
        encryptedToKey.set(dest.value, hash);
      }
    }

    const responsePayment = await this._client.postPayment(payment, options);

    const keys = new Map<string, string>();
    for (const dest of responsePayment.destinations) {
      if (dest.zkId && encryptedToKey.has(dest.value)) {
        keys.set(dest.zkId, encryptedToKey.get(dest.value)!);
      }
    }

    const baseUrl = this._resolveBaseUrl(options);
    const primaryValue = payment.destinations[0]?.value ?? "";
    responsePayment.verifyUrl = this._buildVerifyUrl(
      baseUrl,
      primaryValue,
      keys,
    );
    const verifyLink = responsePayment.verifyUrl;

    return { payment: responsePayment, verifyLink, secret };
  }

  async getPaymentsByQRCode(
    qrText: string,
    options: BrantaClientOptions | null = null,
  ): Promise<Payment[]> {
    const text = qrText.trim();

    let url: URL | null = null;
    try {
      url = new URL(text);
    } catch {
      /* not a URL */
    }

    if (!url)
      return this._getPlainPayments(this._normalizeAddress(text), options);

    if (url.protocol === "bitcoin:" || url.protocol === "lightning:") {
      const brantaId = url.searchParams.get("branta_id");
      const brantaSecret = url.searchParams.get("branta_secret");

      if (brantaId && brantaSecret) {
        const additionalValues: string[] = [];
        const lightning = url.searchParams.get("lightning");
        const bolt12 = url.searchParams.get("bolt12");
        const ark = url.searchParams.get("ark");
        if (lightning) additionalValues.push(lightning);
        if (bolt12) additionalValues.push(bolt12);
        if (ark) additionalValues.push(ark);
        return this._getPaymentsForZk(
          brantaId,
          brantaSecret,
          additionalValues,
          options,
        );
      }

      return this._getPlainPayments(
        this._normalizeAddress(url.pathname),
        options,
      );
    }

    const brantaId = url.searchParams.get("branta_id");
    const brantaSecret = url.searchParams.get("branta_secret");
    if (brantaId && brantaSecret)
      return this.getPayments(brantaId, brantaSecret, options);

    if (url.protocol === "http:" || url.protocol === "https:") {
      const baseUrl = this._resolveBaseUrl(options);
      if (!baseUrl || new URL(baseUrl).origin !== url.origin) {
        return this._getPlainPayments(this._normalizeAddress(text), options);
      }

      const segments = url.pathname
        .split("/")
        .filter(Boolean)
        .map(decodeURIComponent);
      const [version, type, id] = segments;

      if (version === "v2" && id) {
        if (type === "verify") return this._getPlainPayments(id, options);
        if (type === "zk-verify") {
          const secret = new URLSearchParams(url.hash.slice(1)).get("secret");
          if (secret) return this.getPayments(id, secret, options);
          return this._getPlainPayments(id, options);
        }
      }

      const lastSegment = segments.at(-1);
      if (lastSegment) return this._getPlainPayments(lastSegment, options);
    }

    return this._getPlainPayments(this._normalizeAddress(text), options);
  }

  async isApiKeyValid(
    options: BrantaClientOptions | null = null,
  ): Promise<boolean> {
    return this._client.isApiKeyValid(options);
  }

  private async _getPaymentsForZk(
    lookupValue: string,
    encryptionKey: string,
    additionalHashValues: string[],
    options: BrantaClientOptions | null,
  ): Promise<Payment[]> {
    const payments = await this._client.getPayments(lookupValue, options);
    const baseUrl = this._resolveBaseUrl(options);

    for (const payment of payments) {
      const keys = await this._decryptDestinations(
        payment.destinations,
        lookupValue,
        encryptionKey,
        null,
      );
      for (const value of additionalHashValues) {
        await this._decryptHashZkDestinations(
          payment.destinations,
          value,
          keys,
        );
      }
      payment.verifyUrl = this._buildVerifyUrl(baseUrl, lookupValue, keys);
    }

    return payments;
  }

  private async _decryptDestinations(
    destinations: Destination[],
    destinationValue: string,
    encryptionKey: string | null,
    hashZkType: DestinationType | null,
  ): Promise<Map<string, string>> {
    const keys = new Map<string, string>();

    for (const dest of destinations) {
      if (!dest.zk) continue;

      if (dest.type === "bitcoin_address") {
        if (!encryptionKey)
          throw new BrantaPaymentException(
            "Payment is ZK but no destination encryption key was provided.",
          );
        dest.value = await AesEncryption.decrypt(dest.value, encryptionKey);
        if (dest.zkId) keys.set(dest.zkId, encryptionKey);
      } else if (hashZkType && dest.type === hashZkType) {
        const hash = await toNormalizedHash(destinationValue);
        dest.value = await AesEncryption.decrypt(dest.value, hash);
        if (dest.zkId) keys.set(dest.zkId, hash);
      }
    }

    return keys;
  }

  private async _decryptHashZkDestinations(
    destinations: Destination[],
    plainValue: string,
    keys: Map<string, string>,
  ): Promise<void> {
    const hashZkType = getHashZkType(plainValue);
    if (!hashZkType) return;

    const hash = await toNormalizedHash(plainValue);
    for (const dest of destinations) {
      if (!dest.zk || dest.type !== hashZkType) continue;
      dest.value = await AesEncryption.decrypt(dest.value, hash);
      if (dest.zkId) keys.set(dest.zkId, hash);
    }
  }

  private _buildVerifyUrl(
    baseUrl: string,
    lookupValue: string,
    keys: Map<string, string>,
  ): string {
    const encoded = encodeURIComponent(lookupValue);
    let url = `${baseUrl}/v2/verify/${encoded}`;
    if (keys.size > 0) {
      const fragment = Array.from(keys.entries())
        .map(([id, key]) => `k-${id}=${key}`)
        .join("&");
      url += `#${fragment}`;
    }
    return url;
  }

  private _getPlainPayments(
    address: string,
    options: BrantaClientOptions | null,
  ): Promise<Payment[]> {
    const privacy = options?.privacy ?? this._defaultOptions?.privacy;
    if (privacy === "strict" && !getHashZkType(address))
      return Promise.resolve([]);
    return this.getPayments(address, null, options);
  }

  private _resolveBaseUrl(options: BrantaClientOptions | null): string {
    const baseUrl = options?.baseUrl ?? this._defaultOptions?.baseUrl;
    return typeof baseUrl === "string" ? baseUrl : (baseUrl?.url ?? "");
  }

  private _normalizeAddress(text: string): string {
    const lower = text.toLowerCase();
    if (lower.startsWith("lightning:")) return lower.slice("lightning:".length);
    if (lower.startsWith("bitcoin:")) {
      const addr = text.slice("bitcoin:".length);
      const addrLower = addr.toLowerCase();
      return addrLower.startsWith("bc1q") || addrLower.startsWith("bcrt")
        ? addrLower
        : addr;
    }
    if (
      lower.startsWith("lnbc") ||
      lower.startsWith("lntb") ||
      lower.startsWith("lnbcrt") ||
      lower.startsWith("bc1q")
    )
      return lower;
    return text;
  }
}

export default BrantaService;
