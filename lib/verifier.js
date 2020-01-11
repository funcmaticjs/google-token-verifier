const { promisify } = require('util')
const jwt = require('jsonwebtoken')
const jwks = require('jwks-rsa')

class GoogleTokenVerifier {

  constructor(options) {
    options = options || { }
    this.client = jwks({
      jwksUri: options.GOOGLE_JWKS_URI,
      cache: !(options.cache === false),
      cacheMaxEntries: options.cacheMaxEntries || 5, // default value
      cacheMaxAge: options.cacheMaxAge || 10 * 60 * 60 * 1000, // 10 hr default value
    })
    this.client.getSigningKey = promisify(this.client.getSigningKey).bind(this.client)
  }

  decode(token) {
    try {
      let decoded = jwt.decode(token, { complete: true })
      if (!decoded) throw new Error(`Decoded token is null: ${token}`)
      return decoded
    } catch (err) {
      console.error(err)
      throw new Error(`Invalid token format: ${token}`)
    }
  }

  async verify(token) {
    let decoded = this.decode(token)
    let kid = decoded.header.kid
    let key = await this.client.getSigningKey(kid)
    return await jwt.verify(token, key.rsaPublicKey, { complete: true })
  }
}

module.exports = GoogleTokenVerifier
