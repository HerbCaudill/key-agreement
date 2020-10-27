import { base64, hash, randomKey, symmetric } from '@herbcaudill/crypto'
import { TwoPartyProtocol } from './TwoPartyProtocol'

export class KeyAgreementProtocol {
  myId: string
  mySeq = 0
  history: Op[] = []
  nextSeed = ''
  twoPartyProtocol: Map<string, TwoPartyProtocol> = new Map()
  memberSecret: Map<{ sender: string; seq: number; id: string }, string> = new Map()
  ratchet: Map<string, string> = new Map()

  constructor(id: string) {
    this.myId = id
  }

  process(sender: string, { type, seq, payload }: ControlMessage, directMsg: string) {
    const message = { sender, seq, payload, directMsg }
    switch (type) {
      case 'create':
        return this.processCreate(message)
      case 'ack':
        return this.processAck(message)
      case 'update':
        return this.processUpdate(message)
      case 'remove':
        return this.processRemove(message)
      case 'add':
        return this.processAdd(message)
      case 'add-ack':
        return this.processAddAck(message)
      case 'welcome':
        return this.processWelcome(message)
    }
  }

  create(ids: string[]) {
    const controlMsg = { type: 'create', seq: ++this.mySeq, payload: ids }
    const directMsg = this.generateSeed(ids)
    const { i_sender: i } = this.processCreate({ sender: this.myId, seq: this.mySeq, payload: ids })
    return { controlMsg, directMsg, i }
  }

  processCreate({ sender, seq, payload, directMsg }: Message) {
    this.history.push({
      type: 'create',
      sender,
      seq,
      payload,
    })
    return this.processSeed({ sender, seq, directMsg })
  }

  processAck({ sender, seq, payload, directMsg }: Message): ActionResult {
    const { ackId, ackSeq } = payload
    const isCreateAddRemove = true // TODO if (ackId, ackSeq) was a create/add/remove
    if (isCreateAddRemove)
      this.history.push({ type: 'ack', sender, seq, payload: { ackId, ackSeq } })
    const storedSecret = this.memberSecret.get({ sender, seq, id: ackId })
    if (storedSecret) {
      this.memberSecret.delete({ sender, seq, id: ackId })
      return { i_sender: this.updateRatchet(sender, storedSecret) }
    } else if (directMsg) {
      const sentSecret = this.decryptFrom(sender, directMsg)
      return { i_sender: this.updateRatchet(sender, sentSecret) }
    } else return {}
  }

  update() {
    const controlMsg = { type: 'update', seq: ++this.mySeq }
    const recipients = this.memberView(this.myId).filter(id => id !== this.myId)
    const directMsgs = this.generateSeed(recipients)
    const { i_sender: i } = this.processUpdate({ sender: this.myId, seq: this.mySeq })
    return { controlMsg, directMsgs, i }
  }

  processUpdate({ sender, seq, directMsg }: Message): ActionResult {
    return this.processSeed({ sender, seq, directMsg })
  }

  remove(id: string): ActionResult {
    const controlMsg: ControlMessage = { type: 'remove', seq: ++this.mySeq, payload: id }
    const recipients = this.memberView(this.myId).filter(_id => _id !== this.myId && _id !== id)
    const directMsgs = this.generateSeed(recipients)
    const { i_sender: i } = this.processRemove({ sender: this.myId, seq: this.mySeq, payload: id })
    return { controlMsg, directMsgs, i_sender: i }
  }

  processRemove({ sender, seq, payload, directMsg }: Message): ActionResult {
    this.history.push({ type: 'remove', sender, seq, payload })
    return this.processSeed({ sender, seq, directMsg })
  }

  add(id: string): ActionResult {
    const controlMsg: ControlMessage = { type: 'add', seq: ++this.mySeq, payload: id }

    const c = this.encryptTo(id, this.ratchet.get(this.myId)!)
    const history = this.history.concat({
      type: 'add',
      sender: this.myId,
      seq: this.mySeq,
      payload: id,
    })

    const { i_sender: i } = this.processAdd({ sender: this.myId, seq: this.mySeq, payload: id })
    const directMsgs = [{ to: id, cipher: { history, c } }]
    return { controlMsg, directMsgs, i_sender: i }
  }

  processAdd({ sender, seq, payload, directMsg }: Message): ActionResult {
    const id = payload as string
    if (id === this.myId) return this.processWelcome({ sender, seq, directMsg })

    this.history.push({
      type: 'add',
      sender: this.myId,
      seq: this.mySeq,
      payload: id,
    })

    let i_sender: string | undefined = undefined

    if (this.memberView(sender).includes(this.myId)) {
      this.memberSecret.set({ sender, seq, id }, this.updateRatchet(sender, 'welcome'))
      i_sender = this.updateRatchet(sender, 'add')
    }

    if (sender === this.myId) return { i_sender: i_sender }

    const controlMsg: ControlMessage = {
      type: 'add-ack',
      seq: ++this.mySeq,
      payload: { sender, seq },
    }
    const c = this.encryptTo(id, this.ratchet.get(this.myId)!)
    const { i_sender: i } = this.processAddAck({
      sender: this.myId,
      seq: this.mySeq,
      payload: { sender, seq },
    })
    return { controlMsg }
  }

  processAddAck({ sender, seq, payload, directMsg }: Message): ActionResult {
    this.history.push({ type: 'add-ack', sender, seq, payload })
    if (directMsg) this.ratchet.set(sender, this.decryptFrom(sender, directMsg))
    if (this.memberView(sender).includes(this.myId))
      return { i_sender: this.updateRatchet(sender, 'add') }
    else return {}
  }

  processWelcome({ sender, seq, payload, directMsg }: Message): ActionResult {
    const { history, c } = payload as { history: Op[]; c: string }
    this.history = history
    this.ratchet.set(sender, this.decryptFrom(sender, c))
    this.memberSecret.set({ sender, seq, id: this.myId }, this.updateRatchet(sender, 'welcome'))
    const i_sender = this.updateRatchet(sender, 'add')
    const controlMsg: ControlMessage = {
      type: 'ack',
      seq: ++this.mySeq,
      payload: { sender, seq },
    }
    const { i_sender: i_me } = this.processAck({
      sender: this.myId,
      seq: this.mySeq,
      payload: { sender, seq },
    })
    return { controlMsg, i_sender, i_me }
  }

  processSeed({ sender, seq, directMsg }: Message): ActionResult {
    let seed: string

    let recipients = this.memberView(sender).filter(id => id !== sender)

    if (sender === this.myId) {
      seed = this.nextSeed
      this.nextSeed = ''
    } else if (recipients.includes(this.myId)) {
      seed = this.decryptFrom(sender, directMsg!)
    } else {
      return { controlMsg: { type: 'ack', seq: ++this.mySeq, payload: { sender, seq } } }
    }

    for (const id of recipients) {
      const s = hkdf(seed, id)
      this.memberSecret.set({ sender, seq, id }, s)
    }

    const s = hkdf(seed, sender)
    const i_sender = this.updateRatchet(sender, s)
    if (sender === this.myId) return { i_sender: i_sender }

    const controlMsg: ControlMessage = { type: 'ack', seq: ++this.mySeq, payload: { sender, seq } }

    const allMembers = this.memberView(this.myId)
    const directMsgs: DirectMessage[] = [{ to: '', cipher: '' }] // TODO
    // `memberView(myId) \ (recipients ⋃ {sender})`
    // the set of users whose additions I have processed but who were not yet known to sender when they sent the message

    const { i_sender: i_me } = this.processAck({
      sender: this.myId,
      seq: this.mySeq,
      payload: { sender, seq },
    })

    return {
      controlMsg,
      directMsgs,
      i_sender,
      i_me,
    }
  }

  generateSeed(ids: string[]): DirectMessage[] {
    this.nextSeed = randomKey(32)
    return ids.map(id => ({ to: id, cipher: this.encryptTo(id, this.nextSeed) }))
  }

  encryptTo(id: string, plaintext: string): string {
    return this.getTwoPartyProtocol(id).send(plaintext)
  }

  decryptFrom(id: string, cipher: string): string {
    return this.getTwoPartyProtocol(id).receive(cipher)
  }

  updateRatchet(id: string, input: string): string {
    const updateSecret = hkdf(this.ratchet.get(id)!, input)
    this.ratchet.set(id, updateSecret)
    return updateSecret
  }

  memberView(id: string): string[] {
    const ops = this.history.filter(op => {
      const opWasSeenByMember = true // TODO
      // op was sent or acked by id (or the user who added id, if op precedes the add)
      return opWasSeenByMember
    })
    return [] // groupMembership(ops)
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

type MembershipActionType = 'create' | 'remove' | 'add' | 'ack' | 'add-ack'
type ActionType = MembershipActionType | 'update' | 'welcome'

interface ControlMessage {
  type: ActionType
  seq: number
  payload: any // TODO
}

type DirectMessage = {
  to: string
  cipher: any
}

interface Op {
  type: MembershipActionType
  sender: string
  seq: number
  payload: any // TODO
}

interface Message {
  sender: string
  seq: number
  payload?: any // TODO
  directMsg?: string
}

interface ActionResult {
  controlMsg?: ControlMessage
  directMsgs?: DirectMessage[]
  i_sender?: string
  i_me?: string
}

const hkdf = (seed: string, id: string) => base64.encode(hash(seed, id)) // is this good enough to use as a KDF?
