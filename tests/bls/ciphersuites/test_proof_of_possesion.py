import pytest

from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import *
from py_ecc.optimized_bls12_381.optimized_curve import *
from py_ecc.bls.hash_to_curve import hash_to_G2
from hashlib import sha256
import structlog

log = structlog.get_logger()


def test_pop():

    # check pop prove and verify
    sk1 = 2880067194370816120
    pk1 = bls.SkToPk(sk1)

    DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    POP_TAG = b'BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'

    proof1 = bls.PopProve(sk1)
    assert bls.PopVerify(pk1, proof1)

    # private key is the multiplicative identity element
    sk0 = 1
    pk0 = bls.SkToPk(sk0)
    assert pk0 == G1_to_pubkey(G1)
    proof0 = bls.PopProve(sk0)
    log.msg(
        "One private key signed by itself",
        verification_result=bls.PopVerify(pk0, proof0),
    )
    log.msg(
        "One private key is just G1",
        verification_result=bls.PopVerify(G1_to_pubkey(G1), proof0),
    )
    message_point = hash_to_G2(pk0, POP_TAG, hash_function=sha256)
    signature_point = multiply(message_point, sk0)
    message_hash = G2_to_signature(signature_point)

    log.msg(
        "One private key is just G1",
        verification_result=bls.PopVerify(G1_to_pubkey(G1), message_hash),
    )

    # How can this go wrong? If proof of possession verification is done in batch/parallel,
    # rouge proofs (e.g. sum sk == 1 or sum pk == G1_to_pubkey(G1), rogue public keys are possible
    assert bls.PopVerify(G1_to_pubkey(G1), message_hash)


@pytest.mark.parametrize(
    "privkey, pubkey, proof, result",
    [
        (1, bls.SkToPk(1), bls.PopProve(1), True),
        (1, bls.SkToPk(1), bls.PopProve(2), False),
        (1, "hello", bls.PopProve(2), False),
    ],
)
def test_proof_of_possesion(privkey, pubkey, proof, result):
    assert bls.PopVerify(pubkey, proof) == result
