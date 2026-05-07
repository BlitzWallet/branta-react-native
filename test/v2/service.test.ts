import { describe, test, expect, jest, beforeEach } from "@jest/globals";
import { BrantaService } from "../../src/v2/service";
import { IBrantaClient, Destination } from "../../src/v2/types";
import BrantaPaymentException from "../../src/classes/brantaPaymentException";
import BrantaClientOptions from "../../src/classes/brantaClientOptions";
import AesEncryption from "../../src/helpers/aes";

describe("BrantaService", () => {
  let service: BrantaService;
  let mockClient: IBrantaClient;
  let getPaymentsMock: jest.Mock<IBrantaClient['getPayments']>;
  let postPaymentMock: jest.Mock<IBrantaClient['postPayment']>;
  let isApiKeyValidMock: jest.Mock<IBrantaClient['isApiKeyValid']>;

  const defaultOptions: BrantaClientOptions = {
    baseUrl: { url: "http://localhost:3000" },
    defaultApiKey: "test-api-key",
    hmacSecret: null,
    privacy: 'loose',
  } as BrantaClientOptions;

  const testPayments: { destinations: Destination[] }[] = [
    {
      destinations: [
        { value: "123", type: "bitcoin_address", zk: false },
      ],
    },
    {
      destinations: [
        { value: "456", type: "bolt11", zk: false },
      ],
    },
  ];

  beforeEach(() => {
    getPaymentsMock = jest.fn() as jest.Mock<IBrantaClient['getPayments']>;
    postPaymentMock = jest.fn() as jest.Mock<IBrantaClient['postPayment']>;
    isApiKeyValidMock = jest.fn() as jest.Mock<IBrantaClient['isApiKeyValid']>;
    mockClient = {
      getPayments: getPaymentsMock,
      postPayment: postPaymentMock,
      isApiKeyValid: isApiKeyValidMock,
    } as IBrantaClient;
    service = new BrantaService(defaultOptions, mockClient);
    jest.clearAllMocks();
  });

  describe("getPayments", () => {
    test("should return payments from client", async () => {
      getPaymentsMock.mockResolvedValue([...testPayments]);

      const result = await service.getPayments("test-address");

      expect(result).toHaveLength(2);
      expect(result[0].destinations[0].value).toBe("123");
    });

    test("should stamp verifyUrl on returned payments", async () => {
      getPaymentsMock.mockResolvedValue(JSON.parse(JSON.stringify(testPayments)));

      const result = await service.getPayments("test-address");

      expect(result[0].verifyUrl).toBe("http://localhost:3000/v2/verify/test-address");
      expect(result[1].verifyUrl).toBe("http://localhost:3000/v2/verify/test-address");
    });

    test("should throw BrantaPaymentException when privacy is 'strict' via options", async () => {
      const strictOptions = { ...defaultOptions, privacy: 'strict' } as BrantaClientOptions;

      await expect(service.getPayments("some-address", null, strictOptions)).rejects.toThrow(
        BrantaPaymentException
      );
      expect(getPaymentsMock).not.toHaveBeenCalled();
    });

    test("should throw BrantaPaymentException when privacy is 'strict' via defaultOptions", async () => {
      const strictService = new BrantaService(
        { ...defaultOptions, privacy: 'strict' },
        mockClient
      );

      await expect(strictService.getPayments("some-address")).rejects.toThrow(BrantaPaymentException);
      expect(getPaymentsMock).not.toHaveBeenCalled();
    });

    test("should not throw when privacy is 'loose'", async () => {
      getPaymentsMock.mockResolvedValue([]);

      const result = await service.getPayments("some-address");
      expect(result).toEqual([]);
    });

    test("should forward custom options to client", async () => {
      const customOptions = { baseUrl: "https://production.example.com" } as BrantaClientOptions;
      getPaymentsMock.mockResolvedValue([]);

      await service.getPayments("test-address", null, customOptions);

      expect(getPaymentsMock).toHaveBeenCalledWith("test-address", customOptions);
    });

    test("should decrypt ZK destination values when key is provided", async () => {
      const encryptedValue =
        "pQerSFV+fievHP+guYoGJjx1CzFFrYWHAgWrLhn5473Z19M6+WMScLd1hsk808AEF/x+GpZKmNacFBf5BbQ=";
      const payments = [
        {
          destinations: [
            { zk: true, value: encryptedValue },
            { zk: false, value: "plain-value" },
          ],
        },
      ];

      getPaymentsMock.mockResolvedValue(JSON.parse(JSON.stringify(payments)));

      const result = await service.getPayments(encryptedValue, "1234");

      expect(result[0].destinations[0].value).toBe("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
      expect(result[0].destinations[1].value).toBe("plain-value");
    });

    test("should return unmodified payments with no ZK destinations when key is provided", async () => {
      const payments = [
        { destinations: [{ zk: false, value: "plain-value" }] },
      ];

      getPaymentsMock.mockResolvedValue(JSON.parse(JSON.stringify(payments)));

      const result = await service.getPayments("plain-value", "test-secret");

      expect(result[0].destinations[0].value).toBe("plain-value");
    });

    test("should set ZK verifyUrl when encryption key is provided", async () => {
      const encryptedAddress = "pQerSFV+fievHP+guYoGJjx1CzFFrYWHAgWrLhn5473Z19M6+WMScLd1hsk808AEF/x+GpZKmNacFBf5BbQ=";
      const payments = [
        { destinations: [{ zk: true, value: encryptedAddress }] },
      ];

      getPaymentsMock.mockResolvedValue(JSON.parse(JSON.stringify(payments)));

      const result = await service.getPayments(encryptedAddress, "1234");

      expect(result[0].verifyUrl).toBe(
        `http://localhost:3000/v2/zk-verify/${encodeURIComponent(encryptedAddress)}#secret=1234`
      );
    });

    test("should not enforce privacy mode when encryption key is provided", async () => {
      const strictOptions = { ...defaultOptions, privacy: 'strict' } as BrantaClientOptions;
      getPaymentsMock.mockResolvedValue([]);

      await expect(service.getPayments("some-address", "secret", strictOptions)).resolves.toEqual([]);
      expect(getPaymentsMock).toHaveBeenCalled();
    });
  });

  describe("addPayment", () => {
    test("should call client postPayment and always return a secret", async () => {
      const payment = testPayments[0];
      postPaymentMock.mockResolvedValue({ ...payment });

      const result = await service.addPayment(payment);

      expect(postPaymentMock).toHaveBeenCalledWith(payment, null);
      expect(result.payment).toBeDefined();
      expect(result.verifyLink).toBeDefined();
      expect(result.secret).toBeDefined();
    });

    test("should set plain verifyUrl and verifyLink when no ZK destinations", async () => {
      const payment = testPayments[0]; // destinations: [{ value: "123", zk: false }]
      postPaymentMock.mockResolvedValue({ ...payment });

      const result = await service.addPayment(payment);

      expect(result.payment.verifyUrl).toBe('http://localhost:3000/v2/verify/123');
      expect(result.verifyLink).toBe('http://localhost:3000/v2/verify/123');
    });

    test("should encrypt ZK destinations and set ZK verifyUrl and verifyLink", async () => {
      const plainText = "plain-value";
      const payment = {
        destinations: [
          { zk: true, value: plainText },
          { zk: false, value: "other-value" },
        ],
      };

      postPaymentMock.mockImplementation((p) => Promise.resolve(JSON.parse(JSON.stringify(p))));

      const result = await service.addPayment(payment);

      const zkDest = result.payment.destinations.find((d: Destination) => d.zk === true)!;
      expect(await AesEncryption.decrypt(zkDest.value, result.secret)).toBe(plainText);
      expect(result.payment.destinations.find((d: Destination) => d.zk === false)!.value).toBe("other-value");
      expect(result.payment.verifyUrl).toMatch(/^http:\/\/localhost:3000\/v2\/zk-verify\/.+#secret=.+$/);
      expect(result.payment.verifyUrl).toContain(`#secret=${result.secret}`);
      expect(result.verifyLink).toContain("zk-verify");
      expect(result.verifyLink).toContain(`#secret=${result.secret}`);
    });

    test("should not encrypt destinations without zk:true", async () => {
      const payment = {
        destinations: [{ zk: false, value: "do-not-encrypt" }],
      };

      postPaymentMock.mockImplementation((p) => Promise.resolve(JSON.parse(JSON.stringify(p))));

      const result = await service.addPayment(payment);

      expect(result.payment.destinations[0].value).toBe("do-not-encrypt");
    });

    test("should propagate exception from client", async () => {
      const payment = testPayments[0];
      postPaymentMock.mockRejectedValue(new BrantaPaymentException("400"));

      await expect(service.addPayment(payment)).rejects.toThrow(BrantaPaymentException);
    });

    test("should forward custom options to client", async () => {
      const payment = testPayments[0];
      const customOptions = { defaultApiKey: "custom-key" } as BrantaClientOptions;
      postPaymentMock.mockResolvedValue({ ...payment });

      await service.addPayment(payment, customOptions);

      expect(postPaymentMock).toHaveBeenCalledWith(payment, customOptions);
    });

    test("should forward options to client for ZK payment", async () => {
      const payment = {
        destinations: [{ zk: true, value: "plain-value" }],
      };
      const optionsWithHmac = { ...defaultOptions, hmacSecret: "test-secret-key" } as BrantaClientOptions;

      postPaymentMock.mockImplementation((p) => Promise.resolve(JSON.parse(JSON.stringify(p))));

      await service.addPayment(payment, optionsWithHmac);

      expect(postPaymentMock).toHaveBeenCalledWith(expect.any(Object), optionsWithHmac);
    });
  });

  describe("isApiKeyValid", () => {
    test("should delegate to client isApiKeyValid", async () => {
      isApiKeyValidMock.mockResolvedValue(true);

      const result = await service.isApiKeyValid();

      expect(result).toBe(true);
      expect(isApiKeyValidMock).toHaveBeenCalledWith(null);
    });

    test("should return false when client returns false", async () => {
      isApiKeyValidMock.mockResolvedValue(false);

      const result = await service.isApiKeyValid();

      expect(result).toBe(false);
    });

    test("should forward custom options to client", async () => {
      const customOptions = { defaultApiKey: "custom-key" } as BrantaClientOptions;
      isApiKeyValidMock.mockResolvedValue(true);

      await service.isApiKeyValid(customOptions);

      expect(isApiKeyValidMock).toHaveBeenCalledWith(customOptions);
    });
  });

  describe("getPaymentsByQRCode", () => {
    let getPaymentsSpy: jest.SpiedFunction<typeof service.getPayments>;

    beforeEach(() => {
      getPaymentsSpy = jest.spyOn(service, "getPayments").mockResolvedValue([]);
    });

    test("should dispatch ZK query params to getPayments with key", async () => {
      await service.getPaymentsByQRCode("http://example.com?branta_id=myid&branta_secret=mysecret");
      expect(getPaymentsSpy).toHaveBeenCalledWith("myid", "mysecret", null);
    });

    test("should preserve + in branta_id from bitcoin: URI query params", async () => {
      const brantaId = "8RII4RAd8LDsbbBtZY4d+58TI7i7oWb1J43A6JOoZLBMKhUc6Fc5aEjzgUH5r4jouWoRR9ji9zUkswcFhnCrI9petshDfw==";
      const brantaSecret = "ec71c3d2-8704-4879-aec6-d09e4d5073ab";
      await service.getPaymentsByQRCode(
        `bitcoin:BC1Q22WQZZ5PG2ZQVZECR6ZG6QSSUDA07XEXJU4WWQ?amount=0.00002679&pj=https://pay.branta.pro/BTC/pj&branta_id=${brantaId}&branta_secret=${brantaSecret}`
      );
      expect(getPaymentsSpy).toHaveBeenCalledWith(brantaId, brantaSecret, null);
    });

    test("should dispatch /v2/verify/{id} URL to getPayments", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/verify/abc123");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", null, null);
    });

    test("should dispatch /v2/zk-verify/{id}#secret=s URL to getPayments with key", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/zk-verify/abc123#secret=mysecret");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", "mysecret", null);
    });

    test("should dispatch /v2/zk-verify/{id} without secret to getPayments", async () => {
      await service.getPaymentsByQRCode("http://localhost:3000/v2/zk-verify/abc123");
      expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", null, null);
    });

    test("should strip lightning: prefix and lowercase", async () => {
      await service.getPaymentsByQRCode("lightning:LNBC1000N1TEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("lnbc1000n1test", null, null);
    });

    test("should strip bitcoin: and lowercase bc1q address", async () => {
      await service.getPaymentsByQRCode("bitcoin:BC1QTEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("bc1qtest", null, null);
    });

    test("should strip bitcoin: and preserve case for non-bc1q address", async () => {
      await service.getPaymentsByQRCode("bitcoin:3AbcDef");
      expect(getPaymentsSpy).toHaveBeenCalledWith("3AbcDef", null, null);
    });

    test("should lowercase bare lnbc address", async () => {
      await service.getPaymentsByQRCode("LNBC1000N1TEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("lnbc1000n1test", null, null);
    });

    test("should lowercase bare bc1q address", async () => {
      await service.getPaymentsByQRCode("BC1QTEST");
      expect(getPaymentsSpy).toHaveBeenCalledWith("bc1qtest", null, null);
    });

    test("should pass plain address through unchanged", async () => {
      await service.getPaymentsByQRCode("some-payment-id");
      expect(getPaymentsSpy).toHaveBeenCalledWith("some-payment-id", null, null);
    });

    test("should trim surrounding whitespace", async () => {
      await service.getPaymentsByQRCode("  some-payment-id  ");
      expect(getPaymentsSpy).toHaveBeenCalledWith("some-payment-id", null, null);
    });

    test("should decode percent-encoded branta_id from URL search params and pass to getPayments with key", async () => {
      const plaintext = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
      const secret = "mySecret123";

      const encrypted = await AesEncryption.encrypt(plaintext, secret);
      const encodedId = encodeURIComponent(encrypted);

      await service.getPaymentsByQRCode(
        `http://example.com?branta_id=${encodedId}&branta_secret=${secret}`
      );

      expect(getPaymentsSpy).toHaveBeenCalledWith(encrypted, secret, null);
    });

    test("should strip BIP21 query params and normalize bitcoin: URI", async () => {
      await service.getPaymentsByQRCode(
        "bitcoin:BC1QTESTADDRESS?amount=0.00002701&pj=https://example.com/pj"
      );
      expect(getPaymentsSpy).toHaveBeenCalledWith("bc1qtestaddress", null, null);
    });

    test("should decode percent-encoded ZK key from payments/k/ URL and pass to getPayments", async () => {
      const plaintext = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
      const secret = "mySecret123";

      const encrypted = await AesEncryption.encrypt(plaintext, secret);
      const encodedKey = encodeURIComponent(encrypted);

      await service.getPaymentsByQRCode(
        `http://localhost:3000/v2/payments/${encodedKey}`
      );
      expect(getPaymentsSpy).toHaveBeenCalledWith(encrypted, null, null);
    });

    describe("strict privacy mode", () => {
      const strictOptions = { ...defaultOptions, privacy: 'strict' } as BrantaClientOptions;

      test("should allow ZK query param QR (branta_id + branta_secret)", async () => {
        await service.getPaymentsByQRCode(
          "http://example.com?branta_id=myid&branta_secret=mysecret",
          strictOptions
        );
        expect(getPaymentsSpy).toHaveBeenCalledWith("myid", "mysecret", strictOptions);
      });

      test("should allow zk-verify URL with secret", async () => {
        await service.getPaymentsByQRCode(
          "http://localhost:3000/v2/zk-verify/abc123#secret=mysecret",
          strictOptions
        );
        expect(getPaymentsSpy).toHaveBeenCalledWith("abc123", "mysecret", strictOptions);
      });

      test("should block plain address and return []", async () => {
        const result = await service.getPaymentsByQRCode("some-payment-id", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("should block bitcoin: URI and return []", async () => {
        const result = await service.getPaymentsByQRCode("bitcoin:BC1QTEST", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("should block verify URL and return []", async () => {
        const result = await service.getPaymentsByQRCode(
          "http://localhost:3000/v2/verify/abc123",
          strictOptions
        );
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("should block zk-verify URL without secret and return []", async () => {
        const result = await service.getPaymentsByQRCode(
          "http://localhost:3000/v2/zk-verify/abc123",
          strictOptions
        );
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });

      test("should block lightning: address and return []", async () => {
        const result = await service.getPaymentsByQRCode("lightning:LNBC1000N1TEST", strictOptions);
        expect(result).toEqual([]);
        expect(getPaymentsSpy).not.toHaveBeenCalled();
      });
    });
  });
});
