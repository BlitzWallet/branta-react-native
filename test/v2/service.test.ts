import { describe, test, expect, jest, beforeEach } from "@jest/globals";
import { BrantaService } from "../../src/v2/service";
import { IBrantaClient, Destination } from "../../src/v2/types";
import BrantaPaymentException from "../../src/classes/brantaPaymentException";
import BrantaClientOptions from "../../src/classes/brantaClientOptions";
import AesEncryption from "../../src/helpers/aes";
import { toNormalizedHash } from "../../src/helpers/hashZk";

describe("BrantaService", () => {
  let service: BrantaService;
  let mockClient: IBrantaClient;
  let getPaymentsMock: jest.Mock<IBrantaClient['getPayments']>;
  let postPaymentMock: jest.Mock<IBrantaClient['postPayment']>;
  let isApiKeyValidMock: jest.Mock<IBrantaClient['isApiKeyValid']>;

  const defaultOptions = {
    baseUrl: { url: "http://localhost:3000" },
    defaultApiKey: "test-api-key",
    hmacSecret: null,
    privacy: 'loose',
  } as BrantaClientOptions;

  const strictOptions = { ...defaultOptions, privacy: 'strict' } as BrantaClientOptions;

  const BITCOIN_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
  const BOLT11 = "lnbc100n1ptest";
  const ARK_ADDRESS = "ark1testaddress";

  function makePayment(destinations: Partial<Destination>[]) {
    return { destinations: destinations as Destination[] };
  }

  beforeEach(() => {
    getPaymentsMock = jest.fn() as jest.Mock<IBrantaClient['getPayments']>;
    postPaymentMock = jest.fn() as jest.Mock<IBrantaClient['postPayment']>;
    isApiKeyValidMock = jest.fn() as jest.Mock<IBrantaClient['isApiKeyValid']>;
    mockClient = { getPayments: getPaymentsMock, postPayment: postPaymentMock, isApiKeyValid: isApiKeyValidMock } as IBrantaClient;
    service = new BrantaService(defaultOptions, mockClient);
    jest.clearAllMocks();
  });

  // ---------------------------------------------------------------------------
  // getPayments — plain address
  // ---------------------------------------------------------------------------
  describe("getPayments (plain address)", () => {
    test("should return payments and stamp plain verifyUrl", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(BITCOIN_ADDRESS);

      expect(result[0].verifyUrl).toBe(`http://localhost:3000/v2/verify/${BITCOIN_ADDRESS}`);
      expect(result[0].destinations[0].value).toBe(BITCOIN_ADDRESS);
    });

    test("should throw in strict mode for plain address", async () => {
      await expect(service.getPayments(BITCOIN_ADDRESS, null, strictOptions)).rejects.toThrow(BrantaPaymentException);
      expect(getPaymentsMock).not.toHaveBeenCalled();
    });

    test("should throw in strict mode via defaultOptions", async () => {
      const strictService = new BrantaService(strictOptions, mockClient);
      await expect(strictService.getPayments(BITCOIN_ADDRESS)).rejects.toThrow(BrantaPaymentException);
    });

    test("should forward options to client", async () => {
      const custom = { baseUrl: "https://example.com" } as BrantaClientOptions;
      getPaymentsMock.mockResolvedValue([]);
      await service.getPayments(BITCOIN_ADDRESS, null, custom);
      expect(getPaymentsMock).toHaveBeenCalledWith(BITCOIN_ADDRESS, custom);
    });
  });

  // ---------------------------------------------------------------------------
  // getPayments — with destinationEncryptionKey (bitcoin address ZK)
  // ---------------------------------------------------------------------------
  describe("getPayments (with encryption key)", () => {
    test("should decrypt bitcoin_address ZK destination", async () => {
      const secret = "my-uuid-secret";
      const encrypted = await AesEncryption.encrypt(BITCOIN_ADDRESS, secret);
      const payment = makePayment([{ value: encrypted, type: 'bitcoin_address', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(encrypted, secret);

      expect(result[0].destinations[0].value).toBe(BITCOIN_ADDRESS);
    });

    test("should build verifyUrl with #k-{zkId}={key} fragment", async () => {
      const secret = "my-uuid-secret";
      const encrypted = await AesEncryption.encrypt(BITCOIN_ADDRESS, secret);
      const payment = makePayment([{ value: encrypted, type: 'bitcoin_address', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(encrypted, secret);

      expect(result[0].verifyUrl).toBe(
        `http://localhost:3000/v2/verify/${encodeURIComponent(encrypted)}#k-zk1=${secret}`
      );
    });

    test("should throw when bitcoin_address ZK destination has no key", async () => {
      const secret = "my-uuid-secret";
      const encrypted = await AesEncryption.encrypt(BITCOIN_ADDRESS, secret);
      const payment = makePayment([{ value: encrypted, type: 'bitcoin_address', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      await expect(service.getPayments(encrypted)).rejects.toThrow();
    });

    test("should not enforce strict privacy when key is provided", async () => {
      const secret = "my-uuid-secret";
      const encrypted = await AesEncryption.encrypt(BITCOIN_ADDRESS, secret);
      const payment = makePayment([{ value: encrypted, type: 'bitcoin_address', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      await expect(service.getPayments(encrypted, secret, strictOptions)).resolves.toBeDefined();
    });

    test("should not decrypt non-ZK destination even when key is provided", async () => {
      const secret = "my-uuid-secret";
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(BITCOIN_ADDRESS, secret);

      expect(result[0].destinations[0].value).toBe(BITCOIN_ADDRESS);
    });
  });

  // ---------------------------------------------------------------------------
  // getPayments — hash ZK types (bolt11, ark_address)
  // ---------------------------------------------------------------------------
  describe("getPayments (hash ZK — bolt11 / ark_address)", () => {
    test("should encrypt bolt11 lookup value and decrypt ZK destination", async () => {
      const hash = await toNormalizedHash(BOLT11);
      const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
      const encryptedDest = await AesEncryption.encrypt(BOLT11, hash, true);

      const payment = makePayment([{ value: encryptedDest, type: 'bolt11', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(BOLT11);

      expect(getPaymentsMock).toHaveBeenCalledWith(encryptedLookup, null);
      expect(result[0].destinations[0].value).toBe(BOLT11);
    });

    test("should build ZK verifyUrl with bolt11 hash fragment", async () => {
      const hash = await toNormalizedHash(BOLT11);
      const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
      const payment = makePayment([{ value: encryptedLookup, type: 'bolt11', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(BOLT11);

      expect(result[0].verifyUrl).toBe(
        `http://localhost:3000/v2/verify/${encodeURIComponent(encryptedLookup)}#k-zk1=${hash}`
      );
    });

    test("should fall back to plain lookup when ZK returns empty (non-strict)", async () => {
      const hash = await toNormalizedHash(BOLT11);
      const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
      const plainPayment = makePayment([{ value: BOLT11, type: 'bolt11', zk: false }]);

      getPaymentsMock
        .mockResolvedValueOnce([])  // ZK lookup returns nothing
        .mockResolvedValueOnce([JSON.parse(JSON.stringify(plainPayment))]);

      const result = await service.getPayments(BOLT11);

      expect(getPaymentsMock).toHaveBeenNthCalledWith(1, encryptedLookup, null);
      expect(getPaymentsMock).toHaveBeenNthCalledWith(2, BOLT11, null);
      expect(result[0].destinations[0].value).toBe(BOLT11);
    });

    test("should NOT fall back to plain lookup in strict mode", async () => {
      getPaymentsMock.mockResolvedValue([]);

      const result = await service.getPayments(BOLT11, null, strictOptions);

      expect(getPaymentsMock).toHaveBeenCalledTimes(1);
      expect(result).toEqual([]);
    });

    test("should not throw in strict mode for bolt11 (hash ZK)", async () => {
      getPaymentsMock.mockResolvedValue([]);
      await expect(service.getPayments(BOLT11, null, strictOptions)).resolves.toEqual([]);
    });

    test("should not throw in strict mode for ark_address (hash ZK) and use encrypted lookup", async () => {
      const hash = await toNormalizedHash(ARK_ADDRESS);
      const encryptedLookup = await AesEncryption.encrypt(ARK_ADDRESS, hash, true);
      getPaymentsMock.mockResolvedValue([]);

      await expect(service.getPayments(ARK_ADDRESS, null, strictOptions)).resolves.toEqual([]);
      expect(getPaymentsMock).toHaveBeenCalledWith(encryptedLookup, strictOptions);
    });

    test("should not decrypt ZK bolt11 destination when lookup value is not a bolt11", async () => {
      const hash = await toNormalizedHash(BOLT11);
      const encryptedBolt11 = await AesEncryption.encrypt(BOLT11, hash, true);
      const payment = makePayment([{ value: encryptedBolt11, type: 'bolt11', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments("not-a-bolt11-value");

      expect(result[0].destinations[0].value).toBe(encryptedBolt11);
      expect(getPaymentsMock).toHaveBeenCalledWith("not-a-bolt11-value", null);
    });

    test("should not decrypt non-ZK bolt11 destination even when lookup is bolt11", async () => {
      const hash = await toNormalizedHash(BOLT11);
      const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
      const payment = makePayment([{ value: BOLT11, type: 'bolt11', zk: false }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(BOLT11);

      expect(getPaymentsMock).toHaveBeenCalledWith(encryptedLookup, null);
      expect(result[0].destinations[0].value).toBe(BOLT11);
    });

    test("should use plain bolt11 value in verifyUrl after ZK fallback", async () => {
      const hash = await toNormalizedHash(BOLT11);
      const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
      const plainPayment = makePayment([{ value: BOLT11, type: 'bolt11', zk: false }]);

      getPaymentsMock
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([JSON.parse(JSON.stringify(plainPayment))]);

      const result = await service.getPayments(BOLT11);

      expect(getPaymentsMock).toHaveBeenNthCalledWith(1, encryptedLookup, null);
      expect(getPaymentsMock).toHaveBeenNthCalledWith(2, BOLT11, null);
      expect(result[0].verifyUrl).toBe(`http://localhost:3000/v2/verify/${BOLT11}`);
    });

    test("should encrypt ark_address lookup and decrypt ZK destination", async () => {
      const hash = await toNormalizedHash(ARK_ADDRESS);
      const encryptedLookup = await AesEncryption.encrypt(ARK_ADDRESS, hash, true);
      const payment = makePayment([{ value: encryptedLookup, type: 'ark_address', zk: true, zkId: "zk1" }]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(ARK_ADDRESS);

      expect(getPaymentsMock).toHaveBeenCalledWith(encryptedLookup, null);
      expect(result[0].destinations[0].value).toBe(ARK_ADDRESS);
    });

    test("should build multi-key verifyUrl with both bitcoin and bolt11 ZK", async () => {
      const secret = "my-uuid-secret";
      const hash = await toNormalizedHash(BOLT11);
      const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
      const encryptedBitcoin = await AesEncryption.encrypt(BITCOIN_ADDRESS, secret);

      const payment = makePayment([
        { value: encryptedBitcoin, type: 'bitcoin_address', zk: true, zkId: "zk-btc" },
        { value: encryptedLookup, type: 'bolt11', zk: true, zkId: "zk-bolt11" },
      ]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const result = await service.getPayments(BOLT11, secret);

      expect(result[0].verifyUrl).toBe(
        `http://localhost:3000/v2/verify/${encodeURIComponent(encryptedLookup)}#k-zk-btc=${secret}&k-zk-bolt11=${hash}`
      );
    });
  });

  // ---------------------------------------------------------------------------
  // addPayment
  // ---------------------------------------------------------------------------
  describe("addPayment", () => {
    test("plain destinations: no encryption, plain verifyUrl", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }]);
      postPaymentMock.mockResolvedValue(JSON.parse(JSON.stringify(payment)));

      const result = await service.addPayment(payment);

      expect(result.payment.verifyUrl).toBe(`http://localhost:3000/v2/verify/${BITCOIN_ADDRESS}`);
      expect(result.verifyLink).toBe(`http://localhost:3000/v2/verify/${BITCOIN_ADDRESS}`);
      expect(result.secret).toBeDefined();
    });

    test("bitcoin_address ZK: encrypts with UUID, sets verifyUrl with zkId fragment", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: true }]);
      const zkId = "zk-response-1";

      postPaymentMock.mockImplementation((p) => {
        const resp = JSON.parse(JSON.stringify(p));
        resp.destinations[0].zkId = zkId;
        return Promise.resolve(resp);
      });

      const result = await service.addPayment(payment);

      expect(await AesEncryption.decrypt(payment.destinations[0].value, result.secret)).toBe(BITCOIN_ADDRESS);
      expect(result.payment.verifyUrl).toContain(`#k-${zkId}=${result.secret}`);
      expect(result.verifyLink).toBe(result.payment.verifyUrl);
    });

    test("bolt11 ZK: encrypts with deterministic hash, sets verifyUrl with bolt11 hash key", async () => {
      const payment = makePayment([{ value: BOLT11, type: 'bolt11', zk: true }]);
      const hash = await toNormalizedHash(BOLT11);
      const expectedEncrypted = await AesEncryption.encrypt(BOLT11, hash, true);
      const zkId = "zk-bolt11";

      postPaymentMock.mockImplementation((p) => {
        const resp = JSON.parse(JSON.stringify(p));
        resp.destinations[0].zkId = zkId;
        return Promise.resolve(resp);
      });

      const result = await service.addPayment(payment);

      expect(payment.destinations[0].value).toBe(expectedEncrypted);
      expect(await AesEncryption.decrypt(payment.destinations[0].value, hash)).toBe(BOLT11);
      expect(result.payment.verifyUrl).toBe(
        `http://localhost:3000/v2/verify/${encodeURIComponent(expectedEncrypted)}#k-${zkId}=${hash}`
      );
    });

    test("ark_address ZK: encrypts with deterministic hash", async () => {
      const payment = makePayment([{ value: ARK_ADDRESS, type: 'ark_address', zk: true }]);
      const hash = await toNormalizedHash(ARK_ADDRESS);
      const expectedEncrypted = await AesEncryption.encrypt(ARK_ADDRESS, hash, true);
      const zkId = "zk-ark";

      postPaymentMock.mockImplementation((p) => {
        const resp = JSON.parse(JSON.stringify(p));
        resp.destinations[0].zkId = zkId;
        return Promise.resolve(resp);
      });

      await service.addPayment(payment);

      expect(payment.destinations[0].value).toBe(expectedEncrypted);
      expect(await AesEncryption.decrypt(payment.destinations[0].value, hash)).toBe(ARK_ADDRESS);
    });

    test("unsupported ZK type throws before calling client", async () => {
      const payment = makePayment([{ value: "0xdeadbeef", type: 'tether_address', zk: true }]);
      await expect(service.addPayment(payment)).rejects.toThrow(BrantaPaymentException);
      expect(postPaymentMock).not.toHaveBeenCalled();
    });

    test("strict mode with plain destination throws", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }]);
      await expect(service.addPayment(payment, strictOptions)).rejects.toThrow(BrantaPaymentException);
      expect(postPaymentMock).not.toHaveBeenCalled();
    });

    test("strict mode with all ZK destinations succeeds", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: true }]);
      postPaymentMock.mockImplementation((p) => Promise.resolve(JSON.parse(JSON.stringify(p))));
      await expect(service.addPayment(payment, strictOptions)).resolves.toBeDefined();
    });

    test("strict mode with mixed ZK/plain throws", async () => {
      const payment = makePayment([
        { value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: true },
        { value: BOLT11, type: 'bolt11', zk: false },
      ]);
      await expect(service.addPayment(payment, strictOptions)).rejects.toThrow(BrantaPaymentException);
      expect(postPaymentMock).not.toHaveBeenCalled();
    });

    test("propagates exception from client", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }]);
      postPaymentMock.mockRejectedValue(new BrantaPaymentException("500"));
      await expect(service.addPayment(payment)).rejects.toThrow(BrantaPaymentException);
    });

    test("forwards options to client", async () => {
      const payment = makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }]);
      const custom = { defaultApiKey: "custom-key" } as BrantaClientOptions;
      postPaymentMock.mockResolvedValue(JSON.parse(JSON.stringify(payment)));
      await service.addPayment(payment, custom);
      expect(postPaymentMock).toHaveBeenCalledWith(payment, custom);
    });
  });

  // ---------------------------------------------------------------------------
  // isApiKeyValid
  // ---------------------------------------------------------------------------
  describe("isApiKeyValid", () => {
    test("delegates to client", async () => {
      isApiKeyValidMock.mockResolvedValue(true);
      expect(await service.isApiKeyValid()).toBe(true);
      expect(isApiKeyValidMock).toHaveBeenCalledWith(null);
    });

    test("returns false when client returns false", async () => {
      isApiKeyValidMock.mockResolvedValue(false);
      expect(await service.isApiKeyValid()).toBe(false);
    });

    test("forwards custom options", async () => {
      const custom = { defaultApiKey: "custom-key" } as BrantaClientOptions;
      isApiKeyValidMock.mockResolvedValue(true);
      await service.isApiKeyValid(custom);
      expect(isApiKeyValidMock).toHaveBeenCalledWith(custom);
    });
  });

  // ---------------------------------------------------------------------------
  // getPaymentsByQRCode
  // ---------------------------------------------------------------------------
  describe("getPaymentsByQRCode", () => {
    let getPaymentsSpy: jest.SpiedFunction<typeof service.getPayments>;

    beforeEach(() => {
      getPaymentsSpy = jest.spyOn(service, "getPayments").mockResolvedValue([]);
    });

    // http/https URL with branta_id + branta_secret
    test("http URL with ZK params dispatches to getPayments with key", async () => {
      await service.getPaymentsByQRCode("http://example.com?branta_id=myid&branta_secret=mysecret");
      expect(getPaymentsSpy).toHaveBeenCalledWith("myid", "mysecret", null);
    });

    // bitcoin: URI with branta_id + branta_secret calls _getPaymentsForZk (via client directly)
    test("bitcoin: URI with branta_id + branta_secret calls client with branta_id as lookup", async () => {
      getPaymentsMock.mockResolvedValue([]);
      // spy no longer intercepts — the _getPaymentsForZk path calls client directly
      getPaymentsSpy.mockRestore();

      const encId = "encrypted-btc-address";
      const secret = "my-secret";
      await service.getPaymentsByQRCode(`bitcoin:BC1QTESTADDRESS?branta_id=${encId}&branta_secret=${secret}`);

      expect(getPaymentsMock).toHaveBeenCalledWith(encId, null);
    });

    test("bitcoin: URI with ZK params + lightning= decrypts additional bolt11 destinations", async () => {
      getPaymentsSpy.mockRestore();

      const secret = "my-secret";
      const hash = await toNormalizedHash(BOLT11);
      const encBolt11 = await AesEncryption.encrypt(BOLT11, hash, true);
      const encBitcoin = await AesEncryption.encrypt(BITCOIN_ADDRESS, secret);
      const zkId1 = "zk-btc";
      const zkId2 = "zk-bolt11";

      const payment = makePayment([
        { value: encBitcoin, type: 'bitcoin_address', zk: true, zkId: zkId1 },
        { value: encBolt11, type: 'bolt11', zk: true, zkId: zkId2 },
      ]);
      getPaymentsMock.mockResolvedValue([JSON.parse(JSON.stringify(payment))]);

      const qrText = `bitcoin:${BITCOIN_ADDRESS}?branta_id=${encodeURIComponent(encBitcoin)}&branta_secret=${secret}&lightning=${BOLT11}`;
      const result = await service.getPaymentsByQRCode(qrText);

      expect(result[0].destinations[0].value).toBe(BITCOIN_ADDRESS);
      expect(result[0].destinations[1].value).toBe(BOLT11);
      expect(result[0].verifyUrl).toBe(
        `http://localhost:3000/v2/verify/${encodeURIComponent(encBitcoin)}#k-${zkId1}=${secret}&k-${zkId2}=${hash}`
      );
    });

    // lightning: URI dispatches through getPayments hash ZK path
    test("lightning: URI calls getPayments (which does hash ZK lookup)", async () => {
      await service.getPaymentsByQRCode("lightning:lnbc1000n1test");
      expect(getPaymentsSpy).toHaveBeenCalledWith("lnbc1000n1test", null, null);
    });

    // http/https Branta verify URLs
    test("/v2/verify/{id} dispatches to getPayments with no key", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/verify/abc123");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", null, null);
    });

    test("/v2/zk-verify/{id}#secret=s dispatches to getPayments with key", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/zk-verify/abc123#secret=mysecret");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", "mysecret", null);
    });

    test("/v2/zk-verify/{id} without secret falls back to plain lookup", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/zk-verify/abc123");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", null, null);
    });

    // Address normalization
    test("strips lightning: prefix and lowercases", async () => {
      await service.getPaymentsByQRCode("lightning:LNBC1000N1TEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("lnbc1000n1test", null, null);
    });

    test("strips bitcoin: and lowercases bc1q address", async () => {
      await service.getPaymentsByQRCode("bitcoin:BC1QTEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("bc1qtest", null, null);
    });

    test("strips bitcoin: and preserves case for non-bc1q address", async () => {
      await service.getPaymentsByQRCode("bitcoin:3AbcDef");
      expect(getPaymentsSpy).toHaveBeenCalledWith("3AbcDef", null, null);
    });

    test("strips BIP21 query params from bitcoin: URI", async () => {
      await service.getPaymentsByQRCode("bitcoin:BC1QTESTADDRESS?amount=0.001&pj=https://example.com");
      expect(getPaymentsSpy).toHaveBeenCalledWith("bc1qtestaddress", null, null);
    });

    test("lowercases bare lnbc address", async () => {
      await service.getPaymentsByQRCode("LNBC1000N1TEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("lnbc1000n1test", null, null);
    });

    test("lowercases bare bc1q address", async () => {
      await service.getPaymentsByQRCode("BC1QTEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("bc1qtest", null, null);
    });

    test("passes plain address through unchanged", async () => {
      await service.getPaymentsByQRCode("some-payment-id");
      expect(getPaymentsSpy).toHaveBeenCalledWith("some-payment-id", null, null);
    });

    test("trims surrounding whitespace", async () => {
      await service.getPaymentsByQRCode("  some-payment-id  ");
      expect(getPaymentsSpy).toHaveBeenCalledWith("some-payment-id", null, null);
    });

    test("decodes percent-encoded branta_id from http URL", async () => {
      const plaintext = BITCOIN_ADDRESS;
      const secret = "mySecret";
      const encrypted = await AesEncryption.encrypt(plaintext, secret);
      await service.getPaymentsByQRCode(`http://example.com?branta_id=${encodeURIComponent(encrypted)}&branta_secret=${secret}`);
      expect(getPaymentsSpy).toHaveBeenCalledWith(encrypted, secret, null);
    });

    test("last URL segment fallback for unknown path", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/payments/abc123");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", null, null);
    });

    // ---------------------------------------------------------------------------
    // strict privacy mode
    // ---------------------------------------------------------------------------
    describe("strict privacy mode", () => {
      test("allows http URL with ZK params", async () => {
        await service.getPaymentsByQRCode("http://example.com?branta_id=myid&branta_secret=mysecret", strictOptions);
        expect(getPaymentsSpy).toHaveBeenCalledWith("myid", "mysecret", strictOptions);
      });

      test("allows zk-verify URL with secret", async () => {
        await service.getPaymentsByQRCode("http://localhost:3000/v2/zk-verify/abc123#secret=s", strictOptions);
        expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", "s", strictOptions);
      });

      test("allows lightning: bolt11 URI (hash ZK encrypted lookup)", async () => {
        await service.getPaymentsByQRCode("lightning:LNBC1000N1TEST", strictOptions);
        expect(getPaymentsSpy).toHaveBeenCalledWith("lnbc1000n1test", null, strictOptions);
      });

      test("blocks plain bitcoin address and returns []", async () => {
        const result = await service.getPaymentsByQRCode("some-payment-id", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("blocks bitcoin: URI (plain address) and returns []", async () => {
        const result = await service.getPaymentsByQRCode("bitcoin:BC1QTEST", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("blocks /v2/verify URL and returns []", async () => {
        const result = await service.getPaymentsByQRCode("http://localhost:3000/v2/verify/abc123", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("blocks zk-verify URL without secret and returns []", async () => {
        const result = await service.getPaymentsByQRCode("http://localhost:3000/v2/zk-verify/abc123", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("bitcoin: URI with branta_id + branta_secret succeeds in strict mode", async () => {
        getPaymentsSpy.mockRestore();
        getPaymentsMock.mockResolvedValue([makePayment([{ value: BITCOIN_ADDRESS, type: 'bitcoin_address', zk: false }])]);

        const encId = "encrypted-btc-address";
        const secret = "my-secret";
        const result = await service.getPaymentsByQRCode(
          `bitcoin:${BITCOIN_ADDRESS}?branta_id=${encId}&branta_secret=${secret}`,
          strictOptions
        );

        expect(result).toHaveLength(1);
        expect(getPaymentsMock).toHaveBeenCalledWith(encId, strictOptions);
      });

      test("lightning: URI calls client with encrypted bolt11 lookup in strict mode", async () => {
        getPaymentsSpy.mockRestore();
        const hash = await toNormalizedHash(BOLT11);
        const encryptedLookup = await AesEncryption.encrypt(BOLT11, hash, true);
        getPaymentsMock.mockResolvedValue([]);

        await service.getPaymentsByQRCode(`lightning:${BOLT11}`, strictOptions);

        expect(getPaymentsMock).toHaveBeenCalledWith(encryptedLookup, strictOptions);
      });
    });
  });
});
