import { Payload } from '@herbcaudill/crypto'
import { Client } from './Client'
import { ID, NetworkMessage } from './types'

export class Network {
  private clients: Map<ID, Client> = new Map()
  private isActive: boolean = false
  private queuedMessages: NetworkMessage[] = []

  constructor() {}

  connect(client: Client): void {
    this.clients.set(client.id, client)
  }

  send(sender: Client, recipientId: ID, message: Payload): void {
    const recipient = this.clients.get(recipientId)
    if (recipient === undefined)
      throw new Error(`The client '${recipientId}' is not connected to the network.`)
    recipient.receive(sender.id, message)
  }

  // TODO: Shouldn't this be enforcing total order?
  broadcast(sender: Client, message: Payload): void {
    for (const recipient of this.clients.values()) {
      if (recipient !== sender) this.queuedMessages.push({ to: recipient, from: sender, message })
    }
    if (!this.isActive) {
      // prevent recursive calls from reaching this block
      this.isActive = true
      while (this.queuedMessages.length > 0) {
        const { to, from, message } = this.queuedMessages.pop()!
        to.receive(from.id, message)
      }
      this.isActive = false
    }
  }

  numClients(): number {
    return this.clients.size
  }
}
