import BrantaClientOptions from "./classes/brantaClientOptions.js";
import BrantaServerBaseUrl from "./classes/brantaServerBaseUrl.js";
import { BrantaClient } from "./v2/client.js";
import { BrantaService } from "./v2/service.js";

export type { IBrantaClient, IBrantaService, Payment, PaymentResult, ZKPaymentResult, Destination, DestinationType } from "./v2/types.js";
export { BrantaClient, BrantaService, BrantaClientOptions, BrantaServerBaseUrl };
// Deprecated: use BrantaClient
export { BrantaClient as V2BrantaClient };
export default BrantaClient;
