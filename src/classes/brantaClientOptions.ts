import { ServerEnvironment } from "./brantaServerBaseUrl";

export default interface BrantaClientOptions {
  baseUrl?: ServerEnvironment | string | null;
  defaultApiKey?: string | null;
  hmacSecret?: string | null;
  timeout?: number;
}