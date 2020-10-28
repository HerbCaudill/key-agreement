import { ACK, ADD, CREATE, REMOVE } from './constants'
import { groupMembership } from './groupMembership'
import { Op } from './types'

const alice = 'alice'
const bob = 'bob'
const charlie = 'charlie'

describe('groupMembership', () => {
  describe('create', () => {
    it('requires the first op to be group creation', () => {
      const history: Op[] = [{ type: ADD, sender: alice, seq: 1, payload: bob }]
      expect(() => groupMembership(history, alice)).toThrow(/first entry must/i)
    })

    it('only permits the the first op to be group creation', () => {
      const history: Op[] = [
        { type: CREATE, sender: alice, seq: 1, payload: [bob] },
        { type: CREATE, sender: alice, seq: 1, payload: [charlie] },
      ]
      expect(() => groupMembership(history, alice)).toThrow(/only first entry/i)
    })

    it('creates a group with members', () => {
      // Alice creates a group with Bob and Charlie as initial members
      const history: Op[] = [{ type: CREATE, sender: alice, seq: 1, payload: [bob, charlie] }]
      // Alice, Bob and Charlie are in the group
      expect(groupMembership(history, alice)).toEqual([alice, bob, charlie])
    })

    it('creates a group with no other members', () => {
      // Alice creates a group with no other members
      const history: Op[] = [{ type: CREATE, sender: alice, seq: 1, payload: [] }]
      // Alice is alone in her group
      expect(groupMembership(history, alice)).toEqual([alice])
    })
  })

  describe('add', () => {
    it('adds a member', () => {
      const history: Op[] = [
        // Alice creates a group with no other members
        { type: CREATE, sender: alice, seq: 1, payload: [] },
        // Alice adds Bob
        { type: ADD, sender: alice, seq: 2, payload: bob },
      ]
      // Alice and Bob are in the group
      expect(groupMembership(history, alice)).toEqual([alice, bob])
    })

    it(`doesn't get mad if you add the same member twice`, () => {
      const history: Op[] = [
        // Alice creates a group with no other members
        { type: CREATE, sender: alice, seq: 1, payload: [] },
        // Alice adds Bob
        { type: ADD, sender: alice, seq: 2, payload: bob },
        // Alice adds Bob again
        { type: ADD, sender: alice, seq: 3, payload: bob },
      ]
      // Alice and Bob are in the group
      expect(groupMembership(history, alice)).toEqual([alice, bob])
    })

    it('a member can add another member', () => {
      const history: Op[] = [
        // Alice creates a group with Bob as its first member
        { type: CREATE, sender: alice, seq: 1, payload: [bob] },
        // Bob adds Charlie
        { type: ADD, sender: bob, seq: 1, payload: charlie },
      ]
      // Alice and Bob are in the group
      expect(groupMembership(history, bob)).toEqual([alice, bob, charlie])
    })

    it(`assume others don't see an add until they ack it`, () => {
      const history: Op[] = [
        // Alice creates a group with Bob as its first member
        { type: CREATE, sender: alice, seq: 1, payload: [bob] },
        // Bob adds Charlie
        { type: ADD, sender: bob, seq: 1, payload: charlie },
      ]
      // Bob knows he added Charlie, and Charlie knows he was added
      expect(groupMembership(history, bob)).toEqual([alice, bob, charlie])
      expect(groupMembership(history, charlie)).toEqual([alice, bob, charlie])

      // However, Alice doesn't know about Charlie yet
      expect(groupMembership(history, alice)).toEqual([alice, bob])

      // Now Alice acks the add
      history.push({ type: ACK, sender: alice, seq: 2, payload: { sender: bob, seq: 1 } })
      expect(groupMembership(history, alice)).toEqual([alice, bob, charlie])
    })
  })

  describe('remove', () => {
    it('removes a member', () => {
      const history: Op[] = [
        // Alice creates a group with two other members
        { type: CREATE, sender: alice, seq: 1, payload: [bob, charlie] },
        // Alice removes Bob
        { type: REMOVE, sender: alice, seq: 2, payload: bob },
      ]
      // Bob is no longer in the group but Charlie is
      expect(groupMembership(history, alice)).toEqual([alice, charlie])
    })

    it('a member can remove another member', () => {
      const history: Op[] = [
        // Alice creates a group with Bob and Charlie
        { type: CREATE, sender: alice, seq: 1, payload: [bob, charlie] },
        // Bob removes Charlie
        { type: REMOVE, sender: bob, seq: 1, payload: charlie },
      ]
      // Alice and Bob are in the group
      expect(groupMembership(history, bob)).toEqual([alice, bob])
    })

    it('a non-member cannot add another member', () => {
      const history: Op[] = [
        // Alice creates a group
        { type: CREATE, sender: alice, seq: 1, payload: [] },
        // Charlie tries to add Bob
        { type: ADD, sender: charlie, seq: 1, payload: bob },
      ]
      // Bob is not in the group
      expect(groupMembership(history, alice)).toEqual([alice])
    })

    it('a non-member cannot remove another member', () => {
      const history: Op[] = [
        // Alice creates a group with Bob
        { type: CREATE, sender: alice, seq: 1, payload: [bob] },
        // Charlie tries to remove Bob
        { type: REMOVE, sender: charlie, seq: 1, payload: bob },
      ]
      // Bob is still in the group
      expect(groupMembership(history, alice)).toEqual([alice, bob])
    })
  })
})
