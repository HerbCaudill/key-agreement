import { base64 } from '@herbcaudill/crypto'
import msgpack from 'msgpack-lite'

export const pack = (o: any) => base64.encode(msgpack.encode(o))
export const unpack = (s: string) => msgpack.decode(base64.decode(s))
