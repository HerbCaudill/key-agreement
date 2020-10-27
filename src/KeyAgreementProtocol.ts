import { base64, hash, Key, randomKey } from '@herbcaudill/crypto'
import { TwoPartyProtocol } from './TwoPartyProtocol'

export class KeyAgreementProtocol {
  myId: string
  mySeq = 0
  history: Op[] = []
  nextSeed: string | undefined
  twoPartyProtocol: Map<string, TwoPartyProtocol> = new Map()
  memberSecret: Map<{ sender: string; seq: number; id: string }, string> = new Map()
  ratchet: Map<string, string> = new Map()

  constructor(id: string) {
    this.myId = id
  }

  process(controlMsg: ControlMessage, directMsg: string) {
    switch (controlMsg.type) {
      case 'create':
        return this.processCreate(controlMsg, directMsg)
      case 'ack':
        return this.processAck(controlMsg, directMsg)
      case 'update':
        return this.processUpdate(controlMsg, directMsg)
      case 'remove':
        return this.processRemove(controlMsg, directMsg)
      case 'add':
        return this.processAdd(controlMsg, directMsg)
      case 'add-ack':
        return this.processAddAck(controlMsg, directMsg)
      case 'welcome':
        return this.processWelcome(controlMsg)
    }
  }

  newControlMessage({ type, payload }: TypedPayload): ControlMessage {
    return { type, sender: this.myId, seq: ++this.mySeq, payload } as ControlMessage
  }

  create(ids: string[]) {
    const controlMsg = this.newControlMessage({ type: 'create', payload: ids })
    const directMsg = this.generateSeed(ids)
    const { updateSecret_sender } = this.processCreate(controlMsg)
    return { controlMsg, directMsg, updateSecret_sender }
  }

  processCreate(controlMsg: ControlMessage, directMsg?: string) {
    this.history.push(controlMsg)
    const { sender, seq } = controlMsg
    return this.processSeed({ sender, seq }, directMsg)
  }

  processAck(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    const { sender: ackId, seq: ackSeq } = controlMsg.payload as VectorClock
    const { sender, seq } = controlMsg

    const isCreateAddRemove = true // TODO if (id: ackId, seq: ackSeq) was a create/add/remove
    if (isCreateAddRemove) this.history.push(controlMsg)

    const storedSecret = this.memberSecret.get({ sender, seq, id: ackId })
    if (storedSecret) {
      this.memberSecret.delete({ sender, seq, id: ackId })
      return { updateSecret_sender: this.updateRatchet(sender, storedSecret) }
    } else if (directMsg) {
      const sentSecret = this.decryptFrom(sender, directMsg)
      return { updateSecret_sender: this.updateRatchet(sender, sentSecret) }
    } else return {}
  }

  /**
   * Post-compromise update: Send everyone a new seed to use to rotate their keys
   */
  update(): ActionResult {
    const controlMsg = this.newControlMessage({ type: 'update', payload: undefined })
    const recipients = this.memberView(this.myId).filter(id => id !== this.myId) // everyone but me
    const directMsgs = this.generateSeed(recipients)
    const { updateSecret_sender } = this.processUpdate(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  processUpdate({ sender, seq }: ControlMessage, directMsg?: string): ActionResult {
    return this.processSeed({ sender, seq }, directMsg)
  }

  remove(id: string): ActionResult {
    const controlMsg = this.newControlMessage({ type: 'remove', payload: id })

    const recipients = this.memberView(this.myId).filter(_id => _id !== this.myId && _id !== id)
    const directMsgs = this.generateSeed(recipients)
    const { updateSecret_sender: i } = this.processRemove(controlMsg, '')
    return { controlMsg, directMsgs, updateSecret_sender: i }
  }

  processRemove(controlMsg: ControlMessage, directMsg: string): ActionResult {
    this.history.push(controlMsg)
    const { sender, seq } = controlMsg
    return this.processSeed({ sender, seq }, directMsg)
  }

  add(id: string): ActionResult {
    const controlMsg = this.newControlMessage({ type: 'add', payload: id })

    // send them my current ratchet
    const c = this.encryptTo(id, this.ratchet.get(this.myId)!)
    // and the group's membership history
    const history = this.history.concat(controlMsg)

    const { updateSecret_sender } = this.processAdd(controlMsg)
    const directMsgs: DirectMessage[] = [{ to: id, payload: { history, c } }]
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  processAdd(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    const { sender, seq } = controlMsg
    const id = controlMsg.payload as ID

    if (id === this.myId) {
      // I'm the person who was added - process this as a welcome
      return this.processWelcome(controlMsg)
    } else {
      this.history.push(controlMsg)

      let updateSecret_sender: string | undefined = undefined

      // If the sender knows I exist...
      // TODO this doesn't really make sense to me. shouldn't we be updating the ratchet for the person who was added, rather than for the sender?
      if (this.memberView(sender).includes(this.myId)) {
        this.memberSecret.set({ sender, seq, id }, this.updateRatchet(sender, 'welcome'))
        updateSecret_sender = this.updateRatchet(sender, 'add')
      }

      // If I sent the message, just return my new key
      if (sender === this.myId) return { updateSecret_sender }

      const ackMsg = this.newControlMessage({ type: 'add-ack', payload: { sender, seq } })
      const c = this.encryptTo(id, this.ratchet.get(this.myId)!)
      const { updateSecret_me } = this.processAddAck(ackMsg, directMsg)
      return {
        controlMsg: ackMsg,
        directMsgs: [{ to: id, payload: c }],
        updateSecret_sender,
        updateSecret_me,
      }
    }
  }

  processAddAck(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    const { sender } = controlMsg
    this.history.push(controlMsg)

    if (directMsg) this.ratchet.set(sender, this.decryptFrom(sender, directMsg))

    return this.memberView(sender).includes(this.myId)
      ? { updateSecret_sender: this.updateRatchet(sender, 'add') }
      : {}
  }

  processWelcome(controlMsg: ControlMessage): ActionResult {
    const { sender, seq } = controlMsg
    const { history, c } = controlMsg.payload as WelcomePayload
    this.history = history
    this.ratchet.set(sender, this.decryptFrom(sender, c))
    this.memberSecret.set({ sender, seq, id: this.myId }, this.updateRatchet(sender, 'welcome'))
    const updateSecret_sender = this.updateRatchet(sender, 'add')
    const ackMsg = this.newControlMessage({ type: 'ack', payload: { sender, seq } })
    const { updateSecret_sender: updateSecret_me } = this.processAck(ackMsg)
    return { controlMsg: ackMsg, updateSecret_sender, updateSecret_me }
  }

  /**
   * Key rotation. This is called when creating a group, when removing someone, or when there's been a compromise (PCS update).
   */
  processSeed({ sender, seq }: VectorClock, directMsg?: string): ActionResult {
    let seed: string

    let recipients = this.memberView(sender).filter(id => id !== sender)

    const ackMsg: ControlMessage = {
      type: 'ack',
      sender: this.myId,
      seq: ++this.mySeq,
      payload: { sender, seq },
    }

    if (sender === this.myId) {
      // I sent the message, so I know I just generated a new seed - use that
      seed = this.nextSeed!
      this.nextSeed = undefined
    } else if (recipients.includes(this.myId) && directMsg) {
      // I was among the message's intended recipients - get the seed from the direct message
      seed = this.decryptFrom(sender, directMsg)
    } else {
      // The sender doesn't know I exist - just acknowledge receipt
      return { controlMsg: ackMsg }
    }

    // Use the seed to create new secrets for each recipient
    for (const id of recipients) {
      const s = hkdf(seed, id)
      this.memberSecret.set({ sender, seq, id }, s)
    }

    // Ratchet the sender's secret
    const s = hkdf(seed, sender)
    const updateSecret_sender = this.updateRatchet(sender, s)

    // If I sent the message, just return my new key
    if (sender === this.myId) return { updateSecret_sender }

    // for any members I know about but who were not yet known to sender when they sent the message,
    // send them the new secret I have for them
    const allMembers = this.memberView(this.myId)
    const newMembers = allMembers.filter(id => !recipients.includes(id) && sender !== id)
    const directMsgs: DirectMessage[] = newMembers.map(id => ({
      to: id,
      payload: this.memberSecret.get({ sender, seq, id: this.myId }),
    }))

    const { updateSecret_sender: updateSecret_me } = this.processAck(ackMsg)

    return { controlMsg: ackMsg, directMsgs, updateSecret_sender, updateSecret_me }
  }

  /**
   * Randomly generates a new seed; returns direct messages to all IDs containing the new seed
   */
  generateSeed(ids: string[]): DirectMessage[] {
    this.nextSeed = randomKey(32)
    return ids.map(id => {
      const newSecret = this.encryptTo(id, this.nextSeed!)
      return { to: id, payload: newSecret }
    })
  }

  updateRatchet(id: string, input: string): string {
    const updateSecret = hkdf(this.ratchet.get(id)!, input)
    this.ratchet.set(id, updateSecret)
    return updateSecret
  }

  // MEMBERSHIP
  //

  memberView(id: string): string[] {
    const ops = this.history.filter(op => {
      const opWasSeenByMember = true // TODO op was sent or acked by id (or the user who added id, if op precedes the add)
      return opWasSeenByMember
    })
    return [] // TODO groupMembership(ops)
  }

  // ENCRYPTION
  // These are just wrappers around the TwoPartyProtocol, which provides encrypt/decrypt services

  encryptTo(id: string, plaintext: string): string {
    return this.getTwoPartyProtocol(id).send(plaintext)
  }

  decryptFrom(id: string, cipher: string): string {
    return this.getTwoPartyProtocol(id).receive(cipher)
  }

  private getTwoPartyProtocol(id: string): TwoPartyProtocol {
    if (!this.twoPartyProtocol.get(id)) {
      const sk = '' // TODO PKI-SecretKey(this.myId,id)
      const pk = '' // TODO PKI-PublicKey(id, this.myId)
      this.twoPartyProtocol.set(id, new TwoPartyProtocol(sk, pk))
    }
    return this.twoPartyProtocol.get(id)!
  }
}

type ID = string
type CipherText = string
type PlainText = any

type DirectMessage = {
  to: ID
  payload: PlainText | CipherText
}

type VectorClock = {
  sender: ID
  seq: number
}

type WelcomePayload = {
  history: Op[]
  c: Key
}

type TypedPayload =
  | { type: 'create'; payload: ID[] }
  | { type: 'remove'; payload: ID }
  | { type: 'add'; payload: ID }
  | { type: 'ack'; payload: VectorClock }
  | { type: 'add-ack'; payload: VectorClock }
  | { type: 'update'; payload: undefined }
  | { type: 'welcome'; payload: WelcomePayload }

type Op = VectorClock & TypedPayload

type ControlMessage = Op

interface ActionResult {
  controlMsg?: ControlMessage
  directMsgs?: DirectMessage[]
  updateSecret_sender?: string
  updateSecret_me?: string
}

const hkdf = (seed: string, id: string) => base64.encode(hash(seed, id))
