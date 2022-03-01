import { ID, PublicKeyLookup } from './types'
import { Network } from './Network'
import { KeyAgreementProtocol } from './KeyAgreementProtocol'
import { Base64Keypair, Payload } from '@herbcaudill/crypto'
import { TwoPartyProtocol } from './TwoPartyProtocol'

type ClientParams = {
  id: ID
  network: Network
  keys: Base64Keypair
  publicKeyLookup: PublicKeyLookup
}

export class Client {
  id: ID
  network: Network
  keyAgreementProtocol: KeyAgreementProtocol
  twoPartyProtocol: TwoPartyProtocol

  constructor({ id, network, keys, publicKeyLookup }: ClientParams) {
    this.id = id
    this.network = network

    this.keyAgreementProtocol = new KeyAgreementProtocol(id, keys.secretKey, publicKeyLookup)
    this.twoPartyProtocol = new TwoPartyProtocol(keys.secretKey, keys.publicKey)
  }

  send(recipientId: ID, message: Payload) {
    const cipher = this.twoPartyProtocol.send(JSON.stringify(message))
    this.network.send(this, recipientId, message)
  }

  broadcast(message: Payload) {
    this.network.broadcast(this, message)
  }

  receive(senderId: ID, message: string) {
    const receiveResult = this.twoPartyProtocol.receive(message)
  }

  create(ids: ID[]) {
    const { controlMsg, directMsgs } = this.keyAgreementProtocol.create(ids)

    this.broadcast(controlMsg!)
    for (const { to, payload } of directMsgs) this.send(to, payload)
  }

  add(id: ID) {}

  remove(id: ID) {}

  update() {}
}
