export class KxcoVaultError extends Error {
  constructor(message) {
    super(message)
    this.name = 'KxcoVaultError'
  }
}
