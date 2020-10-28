import { ACK, ADD, CREATE, REMOVE } from './constants'
import { ID, Op, VectorClock } from './types'

const groupMembershipReducer = (viewer: ID) => (
  members: Map<ID, MemberInfo>,
  op: Op,
  i: number,
  arr: Op[]
) => {
  const { type, sender, payload } = op

  const add = (idToAdd: ID) => {
    // only members can add another member
    if (!members.has(sender)) return members

    // if the member already exists, do nothing
    if (members.has(idToAdd)) return members

    // add the member
    const updatedMembers = new Map<ID, MemberInfo>(members)
    updatedMembers.set(idToAdd, newMember(idToAdd, sender))
    return updatedMembers
  }

  const remove = (idToRemove: ID) => {
    // only members can remove another member
    if (!members.has(sender)) return members

    const updatedMembers = new Map<ID, MemberInfo>(members)
    updatedMembers.delete(idToRemove)
    return updatedMembers
  }

  switch (type) {
    case CREATE: {
      const ids = payload as ID[]
      const updatedMembers = new Map<ID, MemberInfo>()
      updatedMembers.set(sender, newMember(sender, sender)) // founder
      for (const id of ids) updatedMembers.set(id, newMember(id, sender))
      return updatedMembers
    }

    case ADD: {
      const idToAdd = payload as ID

      // if the viewer isn't the sender or the member being added, only process the add when it's acked
      if (viewer !== sender && viewer !== idToAdd) return members

      return add(idToAdd)
    }

    case REMOVE: {
      const idToRemove = payload as ID

      // if the viewer isn't the sender or the member being removed, only process the remove when it's acked
      if (viewer !== sender && viewer !== idToRemove) return members

      return remove(idToRemove)
    }

    case ACK: {
      // we only care about acks by the viewer
      if (sender !== viewer) return members

      // look up the message being acknowledged
      const { sender: ackedSender, seq: ackedSeq } = payload as VectorClock
      const ackedMessage = arr.find(op => op.sender === ackedSender && op.seq === ackedSeq)
      if (ackedMessage === undefined) return members

      switch (ackedMessage.type) {
        case ADD:
          return add(ackedMessage.payload)
        case REMOVE:
          return remove(ackedMessage.payload)
      }
    }
  }
  // ignore coverage - should never get here
  return members
}

export const groupMembershipInfo = (history: Op[], viewer: ID): Map<ID, MemberInfo> => {
  if (history[0].type !== CREATE) throw new Error('First entry must be of type CREATE')
  if (history.slice(1).some(op => op.type === CREATE))
    throw new Error('Only first entry can be of type CREATE')

  const reducer = groupMembershipReducer(viewer)
  return history.reduce(reducer, new Map<ID, MemberInfo>())
}

export const groupMembership = (history: Op[], viewer: ID) =>
  [...groupMembershipInfo(history, viewer).keys()].sort()

const newMember = (id: ID, addedBy: ID) => ({ id, addedBy, acks: [id, addedBy] })

interface MemberInfo {
  id: ID
  addedBy: ID
  acks: ID[]
}
