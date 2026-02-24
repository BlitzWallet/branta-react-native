import { describe, test, expect } from "@jest/globals";
import BrantaClientOptions from "../../src/classes/brantaClientOptions";
import BrantaServerBaseUrl from "../../src/classes/brantaServerBaseUrl";

describe("BrantaClientOptions", () => {
  test("should create instance with default null values", () => {
    const config: BrantaClientOptions = {};

    expect(config.baseUrl).toBeUndefined();
    expect(config.defaultApiKey).toBeUndefined();
    expect(config.hmacSecret).toBeUndefined();
  });

  test("should create instance with provided values", () => {
    const config: BrantaClientOptions = {
      baseUrl: BrantaServerBaseUrl.Localhost,
      defaultApiKey: "test-key",
      hmacSecret: "test-secret",
    };

    expect(config.baseUrl).toBe(BrantaServerBaseUrl.Localhost);
    expect(config.defaultApiKey).toBe("test-key");
    expect(config.hmacSecret).toBe("test-secret");
  });
});