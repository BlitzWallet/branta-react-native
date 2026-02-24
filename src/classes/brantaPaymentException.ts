class BrantaPaymentException extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "BrantaPaymentException";
  }
}

export default BrantaPaymentException;