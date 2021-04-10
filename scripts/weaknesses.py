from itertools import combinations, count, islice
from math import sqrt, factorial
import numpy

from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import *
from py_ecc.optimized_bls12_381.optimized_curve import *
from py_ecc.bls.hash_to_curve import hash_to_G2
from hashlib import sha256
from timeit import default_timer as timer

from multiprocessing import Pool, cpu_count
from fast_compute import compute as rcompute

import structlog
import logging

timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")
shared_processors = [
    structlog.stdlib.add_log_level,
    timestamper,
]

structlog.configure(
    processors=[
        *shared_processors,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)


formatter = structlog.stdlib.ProcessorFormatter(
    processor=structlog.dev.ConsoleRenderer(),
    foreign_pre_chain=shared_processors,
)

handler1 = logging.StreamHandler()
handler1.setFormatter(formatter)
handler2 = logging.FileHandler("logs/result.log", "w")
handler2.setFormatter(formatter)

root_logger = logging.getLogger()
root_logger.addHandler(handler1)
root_logger.addHandler(handler2)
root_logger.setLevel(logging.INFO)

log = structlog.get_logger("root")


def primes(n):
    """ Returns  a list of primes < n """
    sieve = [True] * n
    for i in range(3, int(n ** 0.5) + 1, 2):
        if sieve[i]:
            sieve[i * i:: 2 * i] = [False] * ((n - i * i - 1) // (2 * i) + 1)
    return [2] + [i for i in range(3, n, 2) if sieve[i]]


def is_prime(n):
    return n > 1 and all(n % i for i in islice(count(2), int(sqrt(n) - 1)))


def combinations_size(n, r):
    return int(factorial(n) / (factorial(n - r) * factorial(r)))


#
# Rust lib 'fast_compute' contains identical function to this one, but
# since it's a compiled python-native shared library I expect Rust to
# be much faster.
# Comparison:
#     Python of primes(30):  54.320 s
#     Rust of primes(30):    14.638 s
#
#def compute(modulus, k):
#    set_size = 0
#    lengths = []
#    for subset in combinations(range(modulus), k):
#        if sum(subset) % modulus == 1:
#            set_size += 1
#            lengths.append(len(subset))
#    return set_size, lengths
#


def test_partitions_of_1_mod_m():
    init = timer()
    log.info(
        "Init",
        number_of_cpus=cpu_count(),
    )

    moduli = primes(30)
    log.info(
        "Got primes",
        amount_of_primes=len(moduli),
        took_to_generate=timer() - init,
        primes=moduli,
    )

    for modulus in moduli:
        assert is_prime(modulus)

    for modulus in moduli:
        power_set_size = 2 ** modulus
        partition_set_size = 0
        lengths = []

        with Pool() as pool:
            # using python:
            # res = pool.starmap(compute, ((modulus, k) for k in range(modulus)))
            # using rust:
            res = pool.starmap(rcompute, ((modulus, k) for k in range(modulus)))
            for ss, l in res:
                partition_set_size += ss
                lengths.extend(l)

        partition_ratio = partition_set_size / power_set_size
        mean_partition_length = numpy.mean(lengths)
        median_partition_length = numpy.median(lengths)

        log.info(
            "Results",
            modulus=modulus,
            power_set_size=power_set_size,
            partition_set_size=partition_set_size,
            median_partition_length=median_partition_length,
            mean_partition_length=mean_partition_length,
            partition_ratio=partition_ratio,
        )
    log.info("Finished", total_time=timer() - init)


# profile the addition of public keys coming from a (given or randomly generated) set of private keys
def test_sum_pks():
    for i in range(100):
        sks = numpy.random.randint(1, 10 ** 18, 2048)  # 10**18 is the max of numpy randint
        pks = [bls.SkToPk(sk.item()) for sk in sks]
        start = timer()
        sum_pks = bls._AggregatePKs(pks)
        sum_pks_G1 = pubkey_to_G1(sum_pks)
        if eq(sum_pks_G1, G1):
            log.msg("sum is one key", pks=pks, sum_pks=sum_pks)
        elif is_inf(sum_pks_G1):
            log.msg("sum is is_inf key", pks=pks, sum_pks=sum_pks)
        end = timer()
        log.msg(
            "time ",
            verification_result=end - start,
        )


if __name__ == "__main__":
    test_partitions_of_1_mod_m()

