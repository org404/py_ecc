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
    proof1 = bls.PopProve(sk1)
    assert bls.PopVerify(pk1, proof1)


    # private key is the multiplicative identity element
    sk0 = 1
    pk0 = bls.SkToPk(sk0)
    assert pk0 == G1_to_pubkey(G1)
    proof0 = bls.PopProve(sk0)
    log.msg(
        "One private key signed by itself",
        verification_result=bls.PopVerify(pk0, proof0)
    )
    log.msg(
        "One private key is just G1",
        verification_result=bls.PopVerify(G1_to_pubkey(G1), proof0)
    )


@pytest.mark.parametrize(
    'privkey, pubkey, proof, result',
    [
        (1,bls.SkToPk(1),bls.PopProve(1), True),
        (1,bls.SkToPk(1),bls.PopProve(2), False),
        (1,"hello",bls.PopProve(2), False),
    ]
)

def test_proof_of_possesion(privkey, pubkey, proof,result):
    assert bls.PopVerify(pubkey, proof) == result