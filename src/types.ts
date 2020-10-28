import { Base64 } from '@herbcaudill/crypto'
import { CREATE, REMOVE, ADD, ACK, ADD_ACK, UPDATE, WELCOME } from './constants'

export type ID = string
export type Key = string

export type CipherText = string
export type PlainText = any

export type DirectMessage = PlainText | CipherText

export type DirectMessageEnvelope = {
  to: ID
  payload: DirectMessage
}

export type VectorClock = {
  sender: ID
  seq: number
}

export type WelcomePayload = {
  history: Op[]
  currentRatchet: CipherText
}

export type TypedPayload =
  | { type: typeof CREATE; payload: ID[] }
  | { type: typeof REMOVE; payload: ID }
  | { type: typeof ADD; payload: ID }
  | { type: typeof ACK; payload: VectorClock }
  | { type: typeof ADD_ACK; payload: VectorClock }
  | { type: typeof UPDATE; payload: undefined }
  | { type: typeof WELCOME; payload: WelcomePayload }

export type Op = VectorClock & TypedPayload

export type ControlMessage = Op

export interface ActionResult {
  controlMsg?: ControlMessage
  directMsgs?: DirectMessageEnvelope[]
  updateSecret_sender?: string
  updateSecret_me?: string
}

export interface PublicKeyLookup {
  set(id: ID, publicKey: Base64): void
  get(id: ID): Base64 | undefined
}
