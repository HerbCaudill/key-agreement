// dummy PKI for testing purposes

import { Base64 } from '@herbcaudill/crypto'
import { ID, PublicKeyLookup } from '../types'

export class MockPublicKeyLookup implements PublicKeyLookup {
  private keys = new Map<ID, Base64>()

  set(id: ID, publicKey: Base64) {
    this.keys.set(id, publicKey)
  }

  get(id: ID) {
    return this.keys.get(id)
  }
}
