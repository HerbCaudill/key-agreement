import { randomKey } from '@herbcaudill/crypto'
import { hkdf } from './hkdf'
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
      case CREATE:
        return this.processCreate(controlMsg, directMsg)
      case ACK:
        return this.processAck(controlMsg, directMsg)
      case UPDATE:
        return this.processUpdate(controlMsg, directMsg)
      case REMOVE:
        return this.processRemove(controlMsg, directMsg)
      case ADD:
        return this.processAdd(controlMsg, directMsg)
      case ADD_ACK:
        return this.processAddAck(controlMsg, directMsg)
      case WELCOME:
        return this.processWelcome(controlMsg)
    }
  }

  // RECEIVE

  /** Create a new group with a starting list of members*/
  create(idsToAdd: string[]) {
    const controlMsg = this.newControlMessage({ type: CREATE, payload: idsToAdd })
    const directMsg = this.generateSeed(idsToAdd)

    const { updateSecret_sender } = this.processCreate(controlMsg)
    return { controlMsg, directMsg, updateSecret_sender }
  }

  /** Post-compromise update: Send everyone a new seed to use to rotate their keys */
  update(): ActionResult {
    const controlMsg = this.newControlMessage({ type: UPDATE, payload: undefined })
    const recipients = this.memberView(this.myId).filter(id => id !== this.myId) // everyone but me
    const directMsgs = this.generateSeed(recipients)

    const { updateSecret_sender } = this.processUpdate(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  /** Remove a member and rotate all keys  */
  remove(idToRemove: string): ActionResult {
    const controlMsg = this.newControlMessage({ type: REMOVE, payload: idToRemove })

    const recipients = this.memberView(this.myId).filter(
      _id => !this.isMe(_id) && _id !== idToRemove
    )
    const directMsgs = this.generateSeed(recipients)

    const { updateSecret_sender } = this.processRemove(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  /** Add a member  */
  add(idToAdd: string): ActionResult {
    const controlMsg = this.newControlMessage({ type: ADD, payload: idToAdd })

    // send them a welcome message
    const currentRatchet = this.encryptTo(idToAdd, this.myRatchet())
    const history = this.history.concat(controlMsg)
    const payload: WelcomePayload = { history, currentRatchet }
    const directMsgs: DirectMessage[] = [{ to: idToAdd, payload }]

    const { updateSecret_sender } = this.processAdd(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  // RECEIVE

  processCreate(controlMsg: ControlMessage, directMsg?: string) {
    this.history.push(controlMsg)
    const { sender, seq } = controlMsg
    return this.processSeed({ sender, seq }, directMsg)
  }

  processAck(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    const clock = controlMsg.payload as VectorClock

    if (this.messageAffectsMembership(clock)) this.history.push(controlMsg)

    const { sender, seq } = controlMsg

    // if this is our own ack, we're done
    if (directMsg === undefined) return {}

    const key = { sender, seq, id: clock.sender }
    const memberSecret =
      this.memberSecret.get(key) ?? // if we have one stored, use that
      this.decryptFrom(sender, directMsg) // otherwise use one they've sent
    // delete anything that we had stored
    this.memberSecret.delete(key)

    // update the ratchet for the sender
    const updateSecret_sender = this.updateRatchet(sender, memberSecret)
    return { updateSecret_sender }
  }

  processUpdate(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    return this.processSeed(controlMsg, directMsg)
  }

  processRemove(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    this.history.push(controlMsg)
    const { sender, seq } = controlMsg
    return this.processSeed({ sender, seq }, directMsg)
  }

  processAdd(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    const { sender, seq } = controlMsg
    const idToAdd = controlMsg.payload as ID

    if (this.isMe(idToAdd)) {
      // I'm the person who was added - process this as a welcome
      return this.processWelcome(controlMsg)
    } else {
      this.history.push(controlMsg)

      let updateSecret_sender: string | undefined = undefined

      // If the sender knows I exist, update their ratchets to account for the welcome & add
      if (this.knowsAboutMe(sender)) {
        this.memberSecret.set({ sender, seq, id: idToAdd }, this.updateRatchet(sender, 'welcome'))
        updateSecret_sender = this.updateRatchet(sender, 'add')
      }

      // If I sent the message, just return my new update secret
      if (this.isMe(sender)) return { updateSecret_sender }

      const ackMsg = this.newControlMessage({ type: ADD_ACK, payload: { sender, seq } })
      const myCurrentRatchet = this.myRatchet()
      const directMsgs = [{ to: idToAdd, payload: this.encryptTo(idToAdd, myCurrentRatchet) }]

      const { updateSecret_me } = this.processAddAck(ackMsg, directMsg)

      return {
        controlMsg: ackMsg,
        directMsgs,
        updateSecret_sender,
        updateSecret_me,
      }
    }
  }

  processAddAck(controlMsg: ControlMessage, directMsg?: string): ActionResult {
    const { sender } = controlMsg
    this.history.push(controlMsg)

    if (directMsg) this.ratchet.set(sender, this.decryptFrom(sender, directMsg))

    // does the sender know I exist?
    return this.knowsAboutMe(sender)
      ? { updateSecret_sender: this.updateRatchet(sender, 'add') }
      : {}
  }

  processWelcome(controlMsg: ControlMessage): ActionResult {
    const { sender, seq } = controlMsg
    const { history, currentRatchet } = controlMsg.payload as WelcomePayload

    // start with the history they've sent
    this.history = history

    // set their current ratchet
    this.ratchet.set(sender, this.decryptFrom(sender, currentRatchet))

    // update their ratchet with the 'welcome' keyword and store that as their secret
    this.memberSecret.set({ sender, seq, id: this.myId }, this.updateRatchet(sender, WELCOME))

    // update their ratchet again with the 'add' keyword and return that as the sender update secret
    const updateSecret_sender = this.updateRatchet(sender, ADD)

    // Get my update secret by acking the welcome
    const ackMsg = this.newControlMessage({ type: ACK, payload: { sender, seq } })
    const { updateSecret_sender: updateSecret_me } = this.processAck(ackMsg)

    return { controlMsg: ackMsg, updateSecret_sender, updateSecret_me }
  }

  /**
   * Key rotation. This is called when creating a group, when removing someone, or when there's been a compromise (PCS update).
   */
  processSeed({ sender, seq }: VectorClock, directMsg?: string): ActionResult {
    let seed: string

    let recipients = this.memberView(sender).filter(id => id !== sender)

    const ackMsg = this.newControlMessage({ type: ACK, payload: { sender, seq } })

    if (this.isMe(sender)) {
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
    if (this.isMe(sender)) return { updateSecret_sender }

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

  private knowsAboutMe(sender: string) {
    return this.memberView(sender).includes(this.myId)
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

  // UTILITY

  private isMe(id: ID) {
    return this.myId === id
  }
  private newControlMessage({ type, payload }: TypedPayload): ControlMessage {
    return { type, sender: this.myId, seq: ++this.mySeq, payload } as ControlMessage
  }

  private myRatchet() {
    return this.ratchet.get(this.myId)!
  }

  // look up a message by its vector clock (sender ID and sequence number)
  private retrieveMessage({ sender, seq }: VectorClock) {
    return this.history.find(op => op.sender === sender && op.seq === seq)
  }

  // checks to see if a given message affects group membership (only create, add, and remove)
  private messageAffectsMembership(clock: VectorClock) {
    const message = this.retrieveMessage(clock)
    if (message === undefined) throw new Error('Message not found ' + JSON.stringify(clock))
    return ['create', 'add', 'remove'].includes(message.type)
  }
}

// TYPES

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
  currentRatchet: CipherText
}

const CREATE = 'CREATE'
const REMOVE = 'REMOVE'
const ADD = 'ADD'
const ACK = 'ACK'
const ADD_ACK = 'ADD_ACK'
const UPDATE = 'UPDATE'
const WELCOME = 'WELCOME'

type TypedPayload =
  | { type: typeof CREATE; payload: ID[] }
  | { type: typeof REMOVE; payload: ID }
  | { type: typeof ADD; payload: ID }
  | { type: typeof ACK; payload: VectorClock }
  | { type: typeof ADD_ACK; payload: VectorClock }
  | { type: typeof UPDATE; payload: undefined }
  | { type: typeof WELCOME; payload: WelcomePayload }

type Op = VectorClock & TypedPayload

type ControlMessage = Op

interface ActionResult {
  controlMsg?: ControlMessage
  directMsgs?: DirectMessage[]
  updateSecret_sender?: string
  updateSecret_me?: string
}
