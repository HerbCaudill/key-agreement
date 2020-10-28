import { ADD, CREATE, REMOVE } from './constants'
import { ID, Op } from './types'

const groupMembershipReducer = (viewer: ID) => (
  members: Map<ID, MemberInfo>,
  op: Op,
  i: number,
  arr: Op[]
) => {
  const { type, sender, payload } = op
  const updatedMembers = new Map<ID, MemberInfo>(members)

  switch (type) {
    case CREATE:
      const ids = payload as ID[]
      updatedMembers.set(sender, newMember(sender, sender)) // founder
      for (const id of ids) updatedMembers.set(id, newMember(id, sender))
      return updatedMembers

    case ADD: {
      // only members can add another member
      if (!members.has(sender)) return members

      const idToAdd = payload as ID

      // if the viewer isn't the sender or the member being added, only process the add when it's acked
      if (viewer !== sender && viewer !== idToAdd) return members

      // if the member already exists, do nothing
      if (members.has(idToAdd)) return members

      // add the member
      updatedMembers.set(idToAdd, newMember(idToAdd, sender))
      return updatedMembers
    }

    case REMOVE: {
      // only members can remove another member
      if (!members.has(sender)) return members

      const idToRemove = payload as ID

      // if the viewer isn't the sender or the member being removed, only process the add when it's acked
      if (viewer !== sender && viewer !== idToRemove) return members

      updatedMembers.delete(idToRemove)
      return updatedMembers
    }

    case ACK: {
    }
  }
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
