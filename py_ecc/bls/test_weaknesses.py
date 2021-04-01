from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls import G2Basic as bls_basic
from py_ecc.bls.g2_primitives import *
from py_ecc.optimized_bls12_381.optimized_curve import *
from .hash_to_curve import hash_to_G2
from hashlib import sha256


def test_poc():
    sk0 = 1234
    sk1 = 1111
    sk2 = 2222
    sk3 = 3333
    sk4 = 4444
    pk1 = bls.SkToPk(sk1)
    pk2 = bls.SkToPk(sk2)
    pk3 = bls.SkToPk(sk3)
    pk4 = bls.SkToPk(sk4)

    # We intentionally choose p as valid signature so that it stays in a correct subgroup.
    msg0 = msg1 = msg2 = msg3 = msg4 = b"message"
    sig0 = bls.Sign(sk0, msg0)
    p = signature_to_G2(sig0)
    print("Consensus attack against proof−of−possession...")
    # msg1 = b"message0"
    # msg2 = b"message0"
    # msg3 = b"message1"
    # msg4 = b"message1"
    sig1 = bls.Sign(sk1, msg1)
    sig2 = bls.Sign(sk2, msg2)
    sig3 = bls.Sign(sk3, msg3)
    sig4 = bls.Sign(sk4, msg4)
    # The attacker creates the following signatures
    # sig1−2P
    sig1prime = G2_to_signature(add(signature_to_G2(sig1), neg(multiply(p, 2))))
    # sig2+p
    sig2prime = G2_to_signature(add(signature_to_G2(sig2), p))
    # sig3−p
    sig3prime = G2_to_signature(add(signature_to_G2(sig3), neg(p)))
    # sig4+2P
    sig4prime = G2_to_signature(add(signature_to_G2(sig4), multiply(p, 2)))

    print("subgroup_check sig1prime:", subgroup_check(signature_to_G2(sig1prime)))

    print("subgroup_check sig2prime:", subgroup_check(signature_to_G2(sig2prime)))

    print("subgroup_checksig3 prime:", subgroup_check(signature_to_G2(sig3prime)))

    print("subgroup_checks ig4 prime:", subgroup_check(signature_to_G2(sig4prime)))

    sig1234prime = bls.Aggregate([sig1prime, sig2prime, sig3prime, sig4prime])

    print(
        "User1 aggregate verify 4 messages:",
        bls.AggregateVerify(
            [pk1, pk2, pk3, pk4], [msg1, msg2, msg3, msg4], sig1234prime
        ),
    )
    sig12prime = bls.Aggregate([sig1prime, sig2prime])
    sig34prime = bls.Aggregate([sig3prime, sig4prime])
    pk12 = bls._AggregatePKs([pk1, pk2])
    pk34 = bls._AggregatePKs([pk3, pk4])
    print(
        "User2 fast aggregate verify the first 2 messages and the last 2 messages.They all return "
        "false so user2 discards sig12prime, sig34prime:",
        bls.FastAggregateVerify([pk1, pk2], msg1, sig12prime),
        bls.FastAggregateVerify([pk3, pk4], msg3, sig34prime),
    )
    print(
        "User2 never executes the this last step because sig12prime and sig34 prime are invalid:",
        bls.AggregateVerify(
            [pk12, pk34], [msg1, msg3], bls.Aggregate([sig12prime, sig34prime])
        ),
    )
    print(
        "Mathematically, we expect both sides return the same result, but they do not:",
        bls.AggregateVerify(
            [pk1, pk2, pk3, pk4], [msg1, msg2, msg3, msg4], sig1234prime
        ),
        bls.FastAggregateVerify([pk1, pk2], msg1, sig12prime)
        and bls.FastAggregateVerify([pk3, pk4], msg3, sig34prime)
        and bls.AggregateVerify(
            [pk12, pk34], [msg1, msg3], bls.Aggregate([sig12prime, sig34prime])
        ),
        "ping",
        ### WTF we can add publickeys? So if i and 30 validators mis-sign, only 1 gets slashed
        # if we  add our keys together but all sigs are valid?
        bls.AggregateVerify(
            [pk12, pk3, pk4], [msg1, msg3], bls.Aggregate([sig12prime, sig34prime])
        ),
        bls.AggregateVerify([pk1], [msg1], sig1234prime),
        bls.AggregateVerify(
            [pk12, pk34], [msg1, msg3], bls.Aggregate([sig12prime, sig34prime])
        ),
    )
    m = b"message"
    sig1 = bls.Sign(sk1, m)
    sig2 = bls.Sign(sk2, m)
    sig3 = bls.Sign(sk3, m)
    # The attacker creates the following modified signatures
    # sig1−2P
    sig1prime = G2_to_signature(
        add(signature_to_G2(sig1), neg(multiply(p, 2)))
    )  # sig2−p
    sig2prime = G2_to_signature(add(signature_to_G2(sig2), neg(p)))  # sig3+3P
    sig3prime = G2_to_signature(add(signature_to_G2(sig3), multiply(p, 3)))
    print(
        bls.FastAggregateVerify(
            [pk1, pk2, pk3], m, bls.Aggregate([sig1prime, sig2prime, sig3prime])
        )
    )
    sig12prime = bls_basic.Aggregate([sig1prime, sig2prime])
    print(bls.FastAggregateVerify([pk1, pk2], m, sig12prime))
    print(
        bls.FastAggregateVerify([pk12, pk3], m, bls.Aggregate([sig12prime, sig3prime]))
    )


def test_2():
    sk0 = 1234
    sk1 = 1111
    # horcrux keys
    pk0 = bls.SkToPk(sk0)
    pk1 = bls.SkToPk(sk1)

    # aggregated_key
    pk01 = bls._AggregatePKs([pk0, pk1])
    sk01 = sk0 + sk1
    m = b"message"
    m0 = b"message0"
    m1 = b"message1"

    # one attestation/proposal for attestation/proposal data
    sig0 = bls.Sign(sk0, m)
    # another attestation for the *same* attestation/proposal data
    sig1 = bls.Sign(sk1, m)
    sigm0 = bls.Sign(sk0, m0)
    sigm1 = bls.Sign(sk1, m1)
    sig01 = bls.Sign(sk01, m)
    # Aggregator aggregates signatueres of pk0 and pk1
    aggregated_signature = bls.Aggregate([sig0, sig1])
    # happy case in a validator, get aggregated_signature from aggregator and verifies against
    # set of pkeys
    print("# the happy case of an aggregated attestation", bls.FastAggregateVerify([pk0, pk1], m,
                                                               aggregated_signature))

    print("sk01 by pk34", bls.FastAggregateVerify([pk01], m, sig01))
    print("sig01 == aggregated_signature ? Yes. So we can aggregate private keys and sign or "
          "aggregate the signatures will be the same. Yay, Pairing! ", sig01 ==
          aggregated_signature)

    print("sk01 by pk0, pk1", bls.FastAggregateVerify([pk0, pk1], m, sig01))
    print("sk01 by pk0", bls.FastAggregateVerify([pk0], m, sig01))

    print(
        "sig0, sig1 by pk01",
        bls.FastAggregateVerify([pk01], m, bls.Aggregate([sig0, sig1])),
    )

    print(
        "sig0, sig1 by pk0, pk1",
        bls.FastAggregateVerify([pk0, pk1], m, bls.Aggregate([sig0, sig1])),
    )
    print(
        "sig0, sig1 by pk0, pk1",
        bls.FastAggregateVerify([pk0, pk1], m, bls.Aggregate([sig0, sig1])),
    )

    print(
        "sig0, sig1, sig01 by pk0, pk1",
        bls.FastAggregateVerify([pk0, pk1], m, bls.Aggregate([sig0, sig1, sig01])),
    )

    print(
        "sig1 by pk01",
        bls.FastAggregateVerify([pk0, pk1], m, bls.Aggregate([sig01])),
    )
    print(
        "AggregateVerify sigm0, sigm1 by pk0, pk1",
        bls.AggregateVerify([pk0, pk1], [m0, m1], bls.Aggregate([sigm0, sigm1])),
    )

    print(
        "AggregateVerify sigm0, sigm1 by pk01",
        bls.AggregateVerify([pk01], [m0, m1], bls.Aggregate([sigm0, sigm1])),
    )

    # Eth2 Proposal

    # *_someone* deposits 32ETH to the ETH1 deposit contract with a bls PK as it's validator key

    # need to wait a bit to become an _active_ validator

    # All validators update their list of active validator, including _someone to the list at
    # some point

    # *_someone* gets randomly selected as proposer and/or aggregator

    # Is it possible for *_someone* to generate conflicting block proposals with an aggregated
    # signature, that is accepted (=verified to true against some pubkey) but is *not*
    # traceable back to *_someone*

    # Is it possible for *_someone* pubkeys to generate valid proposals as well of *_someone*
    # from subkeys (e.g. aggregated summands)?


def test_inverses():
    sk0 = 1
    sk1 = 1111
    sk2 = 3
    # horcrux keys
    one_key = G1_to_pubkey(G1)
    pk1 = bls.SkToPk(sk1)
    pk2 = bls.SkToPk(sk2)

    m = b"message"
    one_sigm = bls.Sign(sk0, m)
    DST=b'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'
    hash = G2_to_signature(hash_to_G2(m, DST, hash_function=sha256))
    sigm1 = bls.Sign(sk1, m)
    sigm2 = bls.Sign(sk2, m)
    # Aggregator aggregates signatueres of pk0 and pk1
    aggregated_signature = bls.Aggregate([hash, sigm1, sigm2])
    # happy case in a validator, get aggregated_signature from aggregator and verifies against
    # set of pkeys
    print("# the happy case of an aggregated attestation", bls.FastAggregateVerify([one_key, pk1, pk2], m,
                                                               bls.Aggregate([hash, sigm1, sigm2])))
