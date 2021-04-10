from itertools import combinations, count, islice
from collections import defaultdict, OrderedDict
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


# "Array-less" median evaluation
def median_from_dict(d: dict):
    values_sorted = OrderedDict(sorted(d.items(), key=lambda t: t[0]))
    index = sum(values_sorted.values()) / 2
    even = index.is_integer()
    x = True
    median = 0
    for value, occurences in values_sorted.items():
        index -= occurences
        if index < 0 and x is True:
            median = value
            break
        elif index == 0 and even is True:
            median = value / 2
            x = False
        elif index < 0 and x is False:
            median += value / 2
            break
    return median

#
# Rust lib 'fast_compute' contains identical function to this one, but
# since that's a compiled python-native shared library I expect Rust to
# be much faster.
# Comparison:
#     Python of primes(30):  50.227 s
#     Rust of primes(30):    12.812 s
#
def compute(modulus, k):
    set_size = 0
    lengths = defaultdict(lambda: 0)
    for subset in combinations(range(modulus), k):
        if sum(subset) % modulus == 1:
            set_size += 1
            lengths[len(subset)] += 1
    # This looks very weird.. they are all the same numbers (lengths).. This might
    # easily be very interesting question to research for optimization.
    # print(f"Differnet values: {len(lengths)} (or {set_size}). Unique values: {len(set(lengths))}.")

    # We have to transform defaultdict back into normal one, because
    # pickle doesn't know how to send it over socket.
    return set_size, dict(lengths.items())


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
        epoch_start = timer()

        power_set_size = 2 ** modulus
        partition_set_size = 0
        lengths = defaultdict(lambda: 0)

        # Computing all the values concurrently and then just summing up results.
        with Pool() as pool:
            # using python (not recommended):
            # f = compute
            # using rust:
            f = rcompute

            res = pool.starmap(f, ((modulus, k) for k in range(modulus)))
            for ss, l in res:
                partition_set_size += ss
                for k, v in l.items():
                    lengths[k] += v

        partition_ratio = partition_set_size / power_set_size
        # Since we are storing everything in dictionary, it's better to use direct mean and median formulas.
        #mean_partition_length = numpy.mean(lengths)
        mean_partition_length = sum(map(lambda x: x[0] * x[1], lengths.items())) / sum(lengths.values())
        #median_partition_length = numpy.median(lengths)
        median_partition_length = median_from_dict(lengths)

        log.info(
            "Results",
            modulus=modulus,
            power_set_size=power_set_size,
            partition_set_size=partition_set_size,
            median_partition_length=median_partition_length,
            mean_partition_length=mean_partition_length,
            partition_ratio=partition_ratio,
        )

        # Log time it took to compute this iteration, but make sure to eliminate spam on the start.
        epoch_time_delta = timer() - epoch_start
        if epoch_time_delta > 60:
            log.info("Time took this epoch", epoch_time_seconds=timer() - epoch_start)
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

