import AesEncryption from "../helpers/aes.js";
import BrantaPaymentException from "../classes/brantaPaymentException.js";
import BrantaClientOptions from "../classes/brantaClientOptions.js";

export interface Destination {
  value: string;
  zk?: boolean;
}

export interface Payment {
  destinations: Destination[];
  ttl?: number;
  description?: string;
  metadata?: Record<string, string>;
}

interface PaymentResponse extends Payment {
  createdAt: Date;
  platform: string;
  platformLogoUrl: string;
}

interface PaymentResult {
  payment: PaymentResponse;
  verifyLink: string;
}

interface ZKPaymentResult extends PaymentResult {
  secret: string;
}

interface HttpClient {
  baseURL: string;
  headers: Record<string, string>;
  timeout: number;
  get(url: string, config?: RequestConfig): Promise<Response>;
  post(url: string, data: unknown, config?: RequestConfig): Promise<Response>;
}

interface RequestConfig {
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export class V2BrantaClient {
  private _defaultOptions: BrantaClientOptions;

  constructor(brantaClientOptions: BrantaClientOptions) {
    this._defaultOptions = brantaClientOptions;
  }

  async getPayments(address: string, options: BrantaClientOptions | null = null): Promise<Payment[]> {
    const httpClient = this._createClient(options);
    const response = await httpClient.get(`/v2/payments/${address}`);

    if (!response.ok || response.headers.get("content-length") === "0") {
      return [];
    }

    const data = await response.json() as Payment[];
    return data;
  }

  async getZKPayment(address: string, secret: string, options: BrantaClientOptions | null = null): Promise<Payment[]> {
    const payments = await this.getPayments(address, options);

    for (const payment of payments) {
      for (const destination of payment?.destinations || []) {
        if (destination.zk === false) continue;
        destination.value = await AesEncryption.decrypt(
          destination.value,
          secret,
        );
      }
    }

    return payments;
  }

  async addPayment(payment: Payment, options: BrantaClientOptions | null = null): Promise<PaymentResult> {
    const httpClient = this._createClient(options);
    this._setApiKey(httpClient, options);
    await this._setHmacHeaders(
      httpClient,
      "POST",
      "/v2/payments",
      payment,
      options,
    );

    const response = await httpClient.post("/v2/payments", payment);

    if (!response.ok) {
      throw new BrantaPaymentException(response.status.toString());
    }

    const responseBody = await response.text();
    const paymentResponse = JSON.parse(responseBody) as PaymentResponse;

    const verifyLink = httpClient.baseURL + "/v2/verify/" + encodeURIComponent(payment.destinations[0].value);

    return { payment: paymentResponse, verifyLink };
  }

  async addZKPayment(payment: Payment, options: BrantaClientOptions | null = null): Promise<ZKPaymentResult> {
    const secret = crypto.randomUUID();

    for (const destination of payment?.destinations || []) {
      if (destination.zk === false) continue;
      destination.value = await AesEncryption.encrypt(
        destination.value,
        secret,
      );
    }

    const responsePayment = (await this.addPayment(payment, options)) as ZKPaymentResult;

    responsePayment.secret = secret;
    responsePayment.verifyLink = responsePayment.verifyLink.replace('verify', 'zk-verify') + "#secret=" + secret;

    return responsePayment;
  }

  async isApiKeyValid(options: BrantaClientOptions | null = null): Promise<boolean> {
    const httpClient = this._createClient(options);
    this._setApiKey(httpClient, options);

    const response = await httpClient.get("/v2/api-keys/health-check");

    return response.ok;
  }

  private _createClient(options: BrantaClientOptions | null): HttpClient {
    const baseUrl = options?.baseUrl ?? this._defaultOptions?.baseUrl;
    const timeout = options?.timeout ?? this._defaultOptions?.timeout ?? 10000;

    const fullBaseUrl = typeof baseUrl === 'string' ? baseUrl : baseUrl?.url;

    if (!fullBaseUrl) {
      throw new Error("Branta: BaseUrl is a required option.");
    }

    return {
      baseURL: fullBaseUrl,
      headers: {},
      timeout,
      async get(url: string, config: RequestConfig = {}): Promise<Response> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
          const response = await fetch(`${this.baseURL}${url}`, {
            method: "GET",
            headers: { ...this.headers, ...config?.headers },
            signal: config?.signal ?? controller.signal,
          });
          return response;
        } catch (error) {
          if (error instanceof Error && error.name === 'AbortError') {
            throw new BrantaPaymentException('Request timeout');
          }
          throw error;
        } finally {
          clearTimeout(timeoutId);
        }
      },
      async post(url: string, data: unknown, config: RequestConfig = {}): Promise<Response> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
          const response = await fetch(`${this.baseURL}${url}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...this.headers,
              ...config?.headers,
            },
            body: JSON.stringify(data),
            signal: config?.signal ?? controller.signal,
          });
          return response;
        } catch (error) {
          if (error instanceof Error && error.name === 'AbortError') {
            throw new BrantaPaymentException('Request timeout');
          }
          throw error;
        } finally {
          clearTimeout(timeoutId);
        }
      },
    };
  }

  private _setApiKey(httpClient: HttpClient, options: BrantaClientOptions | null): void {
    const apiKey =
      options?.defaultApiKey ?? this._defaultOptions?.defaultApiKey;

    if (!apiKey) {
      throw new BrantaPaymentException("Unauthorized");
    }

    httpClient.headers = {
      ...httpClient.headers,
      Authorization: `Bearer ${apiKey}`,
    };
  }

  private async _setHmacHeaders(
    httpClient: HttpClient,
    method: string,
    url: string,
    body: unknown,
    options: BrantaClientOptions | null
  ): Promise<void> {
    const hmacSecret = options?.hmacSecret ?? this._defaultOptions?.hmacSecret;

    if (!hmacSecret) {
      return;
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyString = JSON.stringify(body);
    const message = `${method}|${httpClient.baseURL}${url}|${bodyString}|${timestamp}`;

    const encoder = new TextEncoder();
    const keyData = encoder.encode(hmacSecret);
    const messageData = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    const signatureBuffer = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      messageData,
    );

    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    const signature = signatureArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toLowerCase();

    httpClient.headers = {
      ...httpClient.headers,
      "X-HMAC-Signature": signature,
      "X-HMAC-Timestamp": timestamp,
    };
  }
}

export default V2BrantaClient;