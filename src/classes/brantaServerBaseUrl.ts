const BrantaServerBaseUrl = {
  Staging: { value: 0, url: "https://staging.guardrail.branta.pro" },
  Production: { value: 1, url: "https://guardrail.branta.pro" },
  Localhost: { value: 2, url: "http://localhost:3000" },
} as const;

export type ServerEnvironment = typeof BrantaServerBaseUrl[keyof typeof BrantaServerBaseUrl];

export default BrantaServerBaseUrl;