import { Base64, randomKey } from '@herbcaudill/crypto'
import { ACK, ADD, ADD_ACK, CREATE, REMOVE, UPDATE, WELCOME } from './constants'
import { groupMembership } from './groupMembership'
import { hkdf } from './lib/hkdf'
import { TwoPartyProtocol } from './TwoPartyProtocol'
import {
  ActionResult,
  CipherText,
  ControlMessage,
  DirectMessageEnvelope,
  DirectMessage,
  ID,
  Op,
  PlainText,
  PublicKeyLookup,
  TypedPayload,
  VectorClock,
  WelcomePayload,
} from './types'

// reference implementation: https://github.com/trvedata/key-agreement/blob/main/group_protocol_library/src/main/java/org/trvedata/sgm/FullDcgkaProtocol.java
export class KeyAgreementProtocol {
  myId: ID
  mySeq = 0
  history: Op[] = []
  nextSeed: Base64 | undefined

  twoPartyProtocols: Map<ID, TwoPartyProtocol> = new Map()

  memberSecrets: Map<{ messageId: VectorClock; id: ID }, Base64> = new Map()
  ratchets: Map<ID, Base64> = new Map()
  publicKeyLookup: PublicKeyLookup
  secretKey: any
  // Q: I don't totally understand the difference between this.memberSecret and this.ratchet

  constructor(id: ID, secretKey: Base64, publicKeyLookup: PublicKeyLookup) {
    this.myId = id
    this.secretKey = secretKey
    this.publicKeyLookup = publicKeyLookup
  }

  // SEND

  /** Create a new group with a starting list of members*/
  create(idsToAdd: ID[]) {
    const controlMsg = this.newControlMessage({ type: CREATE, payload: idsToAdd })
    const directMsg = this.generateSeed(idsToAdd)

    const { updateSecret_sender } = this.processCreate(controlMsg)
    return { controlMsg, directMsg, updateSecret_sender }
  }

  /** Post-compromise update: Send everyone a new seed to use to rotate their keys */
  update(): ActionResult {
    const controlMsg = this.newControlMessage({ type: UPDATE, payload: undefined })
    const recipients = this.otherMembers() // everyone but me
    const directMsgs = this.generateSeed(recipients)

    const { updateSecret_sender } = this.processUpdate(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  /** Remove a member and rotate all keys  */
  remove(idToRemove: ID): ActionResult {
    const controlMsg = this.newControlMessage({ type: REMOVE, payload: idToRemove })

    const recipients = this.otherMembers().filter(id => id !== idToRemove) // exclude the member being removed
    const directMsgs = this.generateSeed(recipients)

    const { updateSecret_sender } = this.processRemove(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  /** Add a member  */
  add(idToAdd: ID): ActionResult {
    const controlMsg = this.newControlMessage({ type: ADD, payload: idToAdd })

    // send them a welcome message
    const currentRatchet = this.encryptTo(idToAdd, this.myRatchet())
    const history = this.history.concat(controlMsg)
    const payload: WelcomePayload = { history, currentRatchet }
    const directMsgs: DirectMessageEnvelope[] = [{ to: idToAdd, payload }]

    const { updateSecret_sender } = this.processAdd(controlMsg)
    return { controlMsg, directMsgs, updateSecret_sender }
  }

  // RECEIVE

  process(controlMsg: ControlMessage, directMsg: DirectMessage) {
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

  processCreate(controlMsg: ControlMessage, directMsg?: DirectMessage) {
    this.history.push(controlMsg)
    const { sender, seq } = controlMsg
    return this.processSeed({ sender, seq }, directMsg)
  }

  processAck(controlMsg: ControlMessage, directMsg?: DirectMessage): ActionResult {
    const messageId = controlMsg.payload as VectorClock

    if (this.messageAffectsMembership(messageId)) this.history.push(controlMsg)

    const { sender } = controlMsg

    // if this is our own ack, we're done
    if (directMsg === undefined) return {}

    const k = { messageId, id: messageId.sender }
    const memberSecret =
      this.memberSecrets.get(k) ?? // if we have one stored, use that
      this.decryptFrom(sender, directMsg) // otherwise use the one they've sent

    // delete the stored secret if we had one
    this.memberSecrets.delete(k)

    // update the ratchet for the sender
    const updateSecret_sender = this.updateRatchet(sender, memberSecret)
    return { updateSecret_sender }
  }

  processUpdate(controlMsg: ControlMessage, directMsg?: DirectMessage): ActionResult {
    return this.processSeed(controlMsg, directMsg)
  }

  processRemove(controlMsg: ControlMessage, directMsg?: DirectMessage): ActionResult {
    this.history.push(controlMsg)
    const { sender, seq } = controlMsg
    return this.processSeed({ sender, seq }, directMsg)
  }

  processAdd(controlMsg: ControlMessage, directMsg?: DirectMessage): ActionResult {
    const { sender, seq } = controlMsg
    const idToAdd = controlMsg.payload as ID

    // If I'm the person who was added - process this as a welcome
    if (this.isMe(idToAdd)) return this.processWelcome(controlMsg)

    this.history.push(controlMsg)

    let updateSecret_sender: Base64 | undefined = undefined

    // If the sender knows I exist, update their ratchets
    if (this.knowsAboutMe(sender)) {
      // The added member's initial secret will be the sender's key ratcheted with the WELCOME keyword
      const k = { messageId: { sender, seq }, id: idToAdd }
      this.memberSecrets.set(k, this.updateRatchet(sender, WELCOME))

      // Ratchet the sender's key once more to account for the 'ADD'
      updateSecret_sender = this.updateRatchet(sender, ADD)
    }

    // If I sent the message, just return my new update secret
    if (this.isMe(sender)) return { updateSecret_sender }

    // Send the new member my current ratchet
    const myCurrentRatchet = this.myRatchet()
    const directMsgs = [{ to: idToAdd, payload: this.encryptTo(idToAdd, myCurrentRatchet) }]

    // Acknowledge the add
    const ackMsg = this.newControlMessage({ type: ADD_ACK, payload: { sender, seq } })
    const { updateSecret_me } = this.processAddAck(ackMsg, directMsg)

    return {
      controlMsg: ackMsg,
      directMsgs,
      updateSecret_sender,
      updateSecret_me,
    }
  }

  processAddAck(controlMsg: ControlMessage, directMsg?: DirectMessage): ActionResult {
    const { sender } = controlMsg
    this.history.push(controlMsg)

    // if the sender encloses a direct message, I'm the one that was just added; this is their current ratchet
    if (directMsg) this.ratchets.set(sender, this.decryptFrom(sender, directMsg))

    // if the sender doesn't know I exist, do nothing
    if (!this.knowsAboutMe(sender)) return {}

    return { updateSecret_sender: this.updateRatchet(sender, ADD) }
  }

  processWelcome(controlMsg: ControlMessage): ActionResult {
    const { sender, seq } = controlMsg
    const { history, currentRatchet } = controlMsg.payload as WelcomePayload

    // start with the history they've sent
    this.history = history

    // set the sender's current ratchet to what they've sent
    this.ratchets.set(sender, this.decryptFrom(sender, currentRatchet))

    // update their ratchet with the 'welcome' keyword and store that as my secret
    const k = { messageId: { sender, seq }, id: this.myId }
    this.memberSecrets.set(k, this.updateRatchet(sender, WELCOME))

    // update their ratchet again with the 'add' keyword and return that as the sender update secret
    const updateSecret_sender = this.updateRatchet(sender, ADD)

    // Get my update secret by acking the welcome
    const ackMsg = this.newControlMessage({ type: ACK, payload: { sender, seq } })
    const { updateSecret_sender: updateSecret_me } = this.processAck(ackMsg)

    return { controlMsg: ackMsg, updateSecret_sender, updateSecret_me }
  }

  /**
   * This is called when creating a group, when removing someone, or when there's been a compromise (PCS update).
   * It rotates the keys using the new seed.
   */
  processSeed({ sender, seq }: VectorClock, directMsg?: DirectMessage): ActionResult {
    // Acknowledge the update message
    const ackMsg = this.newControlMessage({ type: ACK, payload: { sender, seq } })

    // If the sender doesn't know I exist, just ack & be done
    if (!this.knowsAboutMe(sender)) return { controlMsg: ackMsg }

    // Determine the new seed
    let recipients = this.memberView(sender).filter(id => id !== sender)
    const seed = this.isMe(sender)
      ? this.useNextSeed() // I sent the message, so I know I just generated a new seed - use that
      : this.decryptFrom(sender, directMsg!) // I was among the message's intended recipients - get the seed from the direct message

    // Use the seed to create and store new secrets for each recipient
    for (const id of recipients) {
      const secret = hkdf(seed, id)
      const k = { messageId: { sender, seq }, id }
      this.memberSecrets.set(k, secret)
    }

    // Create a new secret for the sender, and ratchet it immediately
    const secret = hkdf(seed, sender)
    const updateSecret_sender = this.updateRatchet(sender, secret)

    // If I sent the message, just return my new update
    if (this.isMe(sender)) return { updateSecret_sender }

    // for any members I know about but who were not yet known to sender when they sent the message,
    // send them my current secret
    const allMembers = this.memberView(this.myId)
    const newMembers = allMembers.filter(id => !recipients.includes(id) && sender !== id)
    const myCurrentSecret = this.memberSecrets.get({ messageId: { sender, seq }, id: this.myId })
    const directMsgs = newMembers.map(id => ({
      to: id,
      payload: myCurrentSecret,
    })) as DirectMessageEnvelope[]

    const { updateSecret_sender: updateSecret_me } = this.processAck(ackMsg)

    return { controlMsg: ackMsg, directMsgs, updateSecret_sender, updateSecret_me }
  }

  /** Randomly generate a new seed, and message all IDs with the new seed*/
  generateSeed(ids: ID[]): DirectMessageEnvelope[] {
    this.nextSeed = randomKey(32)
    return ids.map(id => {
      const newSecret = this.encryptTo(id, this.nextSeed!)
      return { to: id, payload: newSecret }
    })
  }

  /** Ratchet once for the given id */
  updateRatchet(id: ID, input: Base64): Base64 {
    const updateSecret = hkdf(this.ratchets.get(id)!, input)
    this.ratchets.set(id, updateSecret)
    return updateSecret
  }

  // MEMBERSHIP
  //

  memberView(viewer: ID): ID[] {
    return groupMembership(this.history, viewer)
  }

  private knowsAboutMe(sender: ID) {
    return this.isMe(sender) || this.memberView(sender).includes(this.myId)
  }

  private otherMembers() {
    return this.memberView(this.myId).filter(id => id !== this.myId)
  }

  // ENCRYPTION
  // These are just wrappers around the TwoPartyProtocol, which provides encrypt/decrypt services

  encryptTo(id: ID, plaintext: PlainText): CipherText {
    return this.getTwoPartyProtocol(id).send(plaintext)
  }

  decryptFrom(id: ID, cipher: CipherText): PlainText {
    return this.getTwoPartyProtocol(id).receive(cipher)
  }

  private getTwoPartyProtocol(id: ID): TwoPartyProtocol {
    if (!this.twoPartyProtocols.get(id)) {
      const sk = '' // TODO PKI-SecretKey(this.myId,id)
      const pk = '' // TODO PKI-PublicKey(id, this.myId)
      this.twoPartyProtocols.set(id, new TwoPartyProtocol(sk, pk))
    }
    return this.twoPartyProtocols.get(id)!
  }

  // UTILITY

  private isMe(id: ID) {
    return this.myId === id
  }
  private newControlMessage({ type, payload }: TypedPayload): ControlMessage {
    return { type, sender: this.myId, seq: ++this.mySeq, payload } as ControlMessage
  }

  private myRatchet() {
    return this.ratchets.get(this.myId)!
  }

  // look up a message by its vector clock (sender ID and sequence number)
  private retrieveMessage({ sender, seq }: VectorClock) {
    return this.history.find(op => op.sender === sender && op.seq === seq)
  }

  // checks to see if a given message affects group membership (only create, add, and remove)
  private messageAffectsMembership(messageId: VectorClock) {
    const message = this.retrieveMessage(messageId)
    if (message === undefined) throw new Error('Message not found ' + JSON.stringify(messageId))
    return ['create', 'add', 'remove'].includes(message.type)
  }

  private useNextSeed() {
    const nextSeed = this.nextSeed
    if (nextSeed === undefined) throw new Error('nextSeed is undefined')
    this.nextSeed = undefined
    return nextSeed
  }
}
