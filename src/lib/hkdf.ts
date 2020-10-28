import { base64, hash } from '@herbcaudill/crypto'

export const hkdf = (seed: string, id: string) => base64.encode(hash(seed, id))
