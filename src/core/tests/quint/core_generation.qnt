// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: BSD-3-Clause
module core_generation {
    import evpl_core.* from "./core"

    pure val PROGRAM_LEN = 64

    action initStream = doReset(TStream, 8192, false)
    action initMessage = doReset(TMessage, 8192, false)
    action initDatagram = doReset(TDatagram, 8192, false)
    action initSmallDatagram = doReset(TDatagram, 4096, false)
    action initPoll = doReset(TStream, 8192, true)

    action transportOp = {
        nondet c = CONN_SLOTS.oneOf()
        nondet side = SIDES.oneOf()
        nondet sz = Set(SzTiny, SzSmall, SzMedium, SzLarge, SzLimit).oneOf()
        nondet mode = (if (isConnected(transport))
            Set(SendBuf, SendV, SendVTakeRef, SendReserveCommit, SendGlobal)
            else Set(SendToEp, SendToEpV)).oneOf()
        nondet drain = Set(DrainRecv, DrainRecvV, DrainPeek, DrainPeekV).oneOf()
        any { listen, stopListen, connect(c, drain), bindPair(c),
              requestSendNotify(c, side), send(c, side, sz, mode),
              close(c, side), finish(c, side), progress, quiesce(QShort) }
    }

    action blockOp = {
        nondet q = BLOCK_QUEUE_SLOTS.oneOf()
        nondet r = REGION_SLOTS.oneOf()
        nondet g = Set(BSeg1, BSeg4, BSeg16).oneOf()
        any { openQueue(q), closeQueue(q), blockRead(q, r, g),
              blockWrite(q, r, g, OpBlockWrite),
              blockWrite(q, r, g, OpBlockWriteSync),
              blockWriteZeroes(q, r), blockWriteZeroesAll(q),
              blockDiscard(q, r), blockFlush(q), progress, quiesce(QShort) }
    }

    action eventOp = {
        nondet t = TIMER_SLOTS.oneOf()
        nondet kind = Set(TOneshot, TPeriodic, TRearm).oneOf()
        nondet delay = Set(DFast, DSlow).oneOf()
        nondet d = DEFERRAL_SLOTS.oneOf()
        nondet b = DOORBELL_SLOTS.oneOf()
        nondet budget = Set(QShort, QLong).oneOf()
        any { addTimer(t, kind, delay), removeTimer(t),
              defer(d, OpDefer, 1), defer(d, OpDeferTwice, 1),
              defer(d, OpDeferReentrant, 2), removeDeferral(d), removeDeferralIdle(d),
              addDoorbell(b), ringDoorbell(b, OpRingDoorbell),
              ringDoorbell(b, OpRingDoorbellTwice), removeDoorbell(b),
              removeDoorbellInCallback(b), setLoopHooks, clearLoopHooks,
              quiesce(budget) }
    }

    // Native spin timing is a separate contract, exercised without providers
    // that may legitimately report additional activity. Portable I/O programs
    // never inherit this scheduling oracle.
    action pollOp = any { addPoll, removePoll, activity, pollPin, pollUnpin,
                          quiesce(QShort), quiesce(QLong) }

    // Configuration pressure: sample large sends without prescribing a burst
    // length or operation order. The converter requires a queued-byte witness.
    action pressureOp = {
        nondet c = CONN_SLOTS.oneOf()
        nondet side = SIDES.oneOf()
        nondet mode = Set(SendV, SendVTakeRef).oneOf()
        any { listen, connect(c, DrainRecvV), send(c, side, SzLarge, mode),
              requestSendNotify(c, side), progress, quiesce(QShort) }
    }

    // Only program boundaries are prescribed. All interior steps select from
    // currently legal transitions. Focus changes sampling, not legality.
    action boundary = if (programStep >= PROGRAM_LEN)
        doReset(transport, maxDatagram, nativePoll)
        else quiesce(QLong)
    val atBoundary = programStep >= PROGRAM_LEN - 1
    action stepTransport = if (atBoundary) boundary else transportOp
    action stepBlock = if (atBoundary) boundary else blockOp
    action stepEvents = if (atBoundary) boundary else eventOp
    action stepPoll = if (atBoundary) boundary else pollOp
    action stepMixed = if (atBoundary) boundary else any { transportOp, blockOp, eventOp }
    action stepPressure = if (atBoundary) boundary else pressureOp
}
