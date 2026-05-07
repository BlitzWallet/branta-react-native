import BrantaClientOptions from "../classes/brantaClientOptions.js";

export type DestinationType = 'bitcoin_address' | 'ln_address' | 'bolt11' | 'bolt12' | 'ln_url' | 'tether_address' | 'ark_address';

export interface Destination {
  value: string;
  type?: DestinationType;
  zk?: boolean;
}

export interface Payment {
  destinations: Destination[];
  ttl?: number;
  description?: string;
  metadata?: Record<string, string>;
  verifyUrl?: string;
  platform?: string;
  platformLogoUrl?: string;
  platformLogoLightUrl?: string;
}

export interface PaymentResult {
  payment: Payment;
  verifyLink: string;
}

export interface ZKPaymentResult extends PaymentResult {
  secret: string;
}

export interface IBrantaClient {
  getPayments(address: string, options?: BrantaClientOptions | null): Promise<Payment[]>;
  postPayment(payment: Payment, options?: BrantaClientOptions | null): Promise<Payment>;
  isApiKeyValid(options?: BrantaClientOptions | null): Promise<boolean>;
}

export interface IBrantaService {
  getPayments(address: string, destinationEncryptionKey?: string | null, options?: BrantaClientOptions | null): Promise<Payment[]>;
  addPayment(payment: Payment, options?: BrantaClientOptions | null): Promise<ZKPaymentResult>;
  getPaymentsByQRCode(qrText: string, options?: BrantaClientOptions | null): Promise<Payment[]>;
  isApiKeyValid(options?: BrantaClientOptions | null): Promise<boolean>;
}
