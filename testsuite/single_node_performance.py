#!/usr/bin/env python

# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import re
import os
import tempfile
import json
import itertools
from typing import Callable, Optional, Tuple, Mapping, Sequence, Any
from tabulate import tabulate
from subprocess import Popen, PIPE, CalledProcessError
from dataclasses import dataclass, field
from enum import Flag, auto


class Flow(Flag):
    # Tests that are run on PRs
    LAND_BLOCKING = auto()
    # Tests that are run continuously on main
    CONTINUOUS = auto()
    # Tests that are run manually when using a smaller representative mode.
    # (i.e. for measuring speed of the machine)
    REPRESENTATIVE = auto()
    # Tests used for mainnet hardware evaluation
    MAINNET = auto()
    # Tests used for mainnet hardware evaluation
    MAINNET_LARGE_DB = auto()
    # Tests for Agg V2 performance
    AGG_V2 = auto()
    # Test resource groups
    RESOURCE_GROUPS = auto()


# Tests that are run on LAND_BLOCKING and continuously on main
LAND_BLOCKING_AND_C = Flow.LAND_BLOCKING | Flow.CONTINUOUS

SELECTED_FLOW = Flow[os.environ.get("FLOW", default="LAND_BLOCKING")]

print(f"Executing flow: {SELECTED_FLOW}")
IS_MAINNET = SELECTED_FLOW in [Flow.MAINNET, Flow.MAINNET_LARGE_DB]
SOURCE = os.environ.get("SOURCE", default="LOCAL")
if SOURCE not in ["ADHOC", "CI", "LOCAL"]:
    print(f"Unrecogznied source {SOURCE}")
    exit(1)

RUNNER_NAME = os.environ.get("RUNNER_NAME", default="none")

DEFAULT_NUM_INIT_ACCOUNTS = (
    "100000000" if SELECTED_FLOW == Flow.MAINNET_LARGE_DB else "2000000"
)
DEFAULT_MAX_BLOCK_SIZE = "10000"

MAX_BLOCK_SIZE = int(os.environ.get("MAX_BLOCK_SIZE", default=DEFAULT_MAX_BLOCK_SIZE))
NUM_BLOCKS = int(os.environ.get("NUM_BLOCKS_PER_TEST", default=15))
NUM_BLOCKS_DETAILED = 10
NUM_ACCOUNTS = max(
    [
        int(os.environ.get("NUM_INIT_ACCOUNTS", default=DEFAULT_NUM_INIT_ACCOUNTS)),
        (2 + 2 * NUM_BLOCKS) * MAX_BLOCK_SIZE,
    ]
)
MAIN_SIGNER_ACCOUNTS = 2 * MAX_BLOCK_SIZE

NOISE_LOWER_LIMIT = 0.98 if IS_MAINNET else 0.8
NOISE_LOWER_LIMIT_WARN = 0.9
# If you want to calibrate the upper limit for perf improvement, you can
# increase this value temporarily (i.e. to 1.3) and readjust back after a day or two of runs
NOISE_UPPER_LIMIT = 1.15
NOISE_UPPER_LIMIT_WARN = 1.05

SKIP_WARNS = IS_MAINNET
SKIP_PERF_IMPROVEMENT_NOTICE = IS_MAINNET

# bump after a perf improvement, so you can easily distinguish runs
# that are on top of this commit
CODE_PERF_VERSION = "v6"

# default to using production number of execution threads for assertions
NUMBER_OF_EXECUTION_THREADS = int(
    os.environ.get("NUMBER_OF_EXECUTION_THREADS", default=32)
)

if os.environ.get("DETAILED"):
    EXECUTION_ONLY_NUMBER_OF_THREADS = [1, 2, 4, 8, 16, 32, 48, 60]
else:
    EXECUTION_ONLY_NUMBER_OF_THREADS = []

if os.environ.get("RELEASE_BUILD"):
    BUILD_FLAG = "--release"
    BUILD_FOLDER = "target/release"
else:
    BUILD_FLAG = "--profile performance"
    BUILD_FOLDER = "target/performance"

if os.environ.get("PROD_DB_FLAGS"):
    DB_CONFIG_FLAGS = ""
else:
    DB_CONFIG_FLAGS = "--enable-storage-sharding"

if os.environ.get("DISABLE_FA_APT"):
    FEATURE_FLAGS = ""
    SKIP_NATIVE = False
else:
    FEATURE_FLAGS = "--enable-feature NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE --enable-feature OPERATIONS_DEFAULT_TO_FA_APT_STORE"
    SKIP_NATIVE = True

if os.environ.get("ENABLE_PRUNER"):
    DB_PRUNER_FLAGS = "--enable-state-pruner --enable-ledger-pruner --enable-epoch-snapshot-pruner --ledger-pruning-batch-size 10000 --state-prune-window 3000000 --epoch-snapshot-prune-window 3000000 --ledger-prune-window 3000000"
else:
    DB_PRUNER_FLAGS = ""

HIDE_OUTPUT = os.environ.get("HIDE_OUTPUT")
SKIP_MOVE_E2E = os.environ.get("SKIP_MOVE_E2E")


@dataclass(frozen=True)
class RunGroupKey:
    transaction_type: str
    module_working_set_size: int = field(default=1)
    executor_type: str = field(default="VM")


@dataclass(frozen=True)
class RunGroupKeyExtra:
    transaction_type_override: Optional[str] = field(default=None)
    transaction_weights_override: Optional[str] = field(default=None)
    sharding_traffic_flags: Optional[str] = field(default=None)


@dataclass
class RunGroupConfig:
    key: RunGroupKey
    included_in: Flow
    expected_tps: Optional[float] = field(default=None)
    key_extra: RunGroupKeyExtra = field(default_factory=RunGroupKeyExtra)
    waived: bool = field(default=False)


# numbers are based on the machine spec used by github action
# Local machine numbers will be different.
#
# Calibrate using median value from
# Humio: https://gist.github.com/igor-aptos/7b12ca28de03894cddda8e415f37889e
# Exporting as CSV and copying to the table below.
# If there is one or few tests that need to be recalibrated, it's recommended to update
# only their lines, as to not add unintentional drift to other tests.
#
# Dashboard: https://aptoslabs.grafana.net/d/fdf2e5rdip5vkd/single-node-performance-benchmark?orgId=1
# fmt: off

# 0-indexed
CALIBRATED_TPS_INDEX = -1
CALIBRATED_COUNT_INDEX = -4
CALIBRATED_MIN_RATIO_INDEX = -3
CALIBRATED_MAX_RATIO_INDEX = -2
CALIBRATION_SEPARATOR = "	"

# transaction_type	module_working_set_size	executor_type	count	min_ratio	max_ratio	median
CALIBRATION = """
no-op	1	VM	34	0.841	1.086	42046.2
no-op	1000	VM	33	0.857	1.026	23125.1
apt-fa-transfer	1	VM	34	0.843	1.057	29851.6
account-generation	1	VM	34	0.843	1.046	24134.9
account-resource32-b	1	VM	34	0.803	1.089	37283.8
modify-global-resource	1	VM	34	0.841	1.017	2854.7
modify-global-resource	100	VM	34	0.844	1.035	36514.1
publish-package	1	VM	34	0.915	1.049	143.4
mix_publish_transfer	1	VM	34	0.912	1.131	2149.7
batch100-transfer	1	VM	33	0.823	1.037	754.2
vector-picture30k	1	VM	33	0.892	1.018	112.4
vector-picture30k	100	VM	34	0.706	1.03	2050.1
smart-table-picture30-k-with200-change	1	VM	34	0.959	1.057	21.5
smart-table-picture30-k-with200-change	100	VM	34	0.9	1.021	412.2
modify-global-resource-agg-v2	1	VM	34	0.729	1.076	39288.2
modify-global-flag-agg-v2	1	VM	34	0.948	1.016	5598.2
modify-global-bounded-agg-v2	1	VM	34	0.881	1.06	9968.4
modify-global-milestone-agg-v2	1	VM	34	0.831	1.029	29575.5
resource-groups-global-write-tag1-kb	1	VM	34	0.933	1.051	9285.8
resource-groups-global-write-and-read-tag1-kb	1	VM	34	0.9	1.016	6353
resource-groups-sender-write-tag1-kb	1	VM	34	0.845	1.163	20568.6
resource-groups-sender-multi-change1-kb	1	VM	34	0.888	1.116	17029.7
token-v1ft-mint-and-transfer	1	VM	34	0.853	1.029	1455.7
token-v1ft-mint-and-transfer	100	VM	34	0.801	1.021	20418.7
token-v1nft-mint-and-transfer-sequential	1	VM	34	0.881	1.023	884.4
token-v1nft-mint-and-transfer-sequential	100	VM	34	0.85	1.021	14733.1
coin-init-and-mint	1	VM	35	0.839	1.056	31116.2
coin-init-and-mint	100	VM	35	0.788	1.04	25367
fungible-asset-mint	1	VM	35	0.861	1.043	27493.2
fungible-asset-mint	100	VM	35	0.865	1.033	22113.3
no-op5-signers	1	VM	34	0.825	1.104	41817.6
token-v2-ambassador-mint	1	VM	35	0.864	1.026	18187.6
token-v2-ambassador-mint	100	VM	35	0.894	1.033	16597.8
liquidity-pool-swap	1	VM	34	0.894	1.026	965
liquidity-pool-swap	100	VM	35	0.893	1.026	11439.4
liquidity-pool-swap-stable	1	VM	36	0.897	1.018	945.1
liquidity-pool-swap-stable	100	VM	36	0.824	1.031	11196.4
deserialize-u256	1	VM	36	0.881	1.06	41062.1
no-op-fee-payer	1	VM	36	0.863	1.031	2141.3
no-op-fee-payer	100	VM	36	0.898	1.02	28717.2
"""

# when adding a new test, add estimated expected_tps to it, as well as waived=True.
# And then after a day or two - add calibration result for it above, removing expected_tps/waived fields.

DEFAULT_MODULE_WORKING_SET_SIZE = 100

TESTS = [
    RunGroupConfig(key=RunGroupKey("no-op"), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("no-op", module_working_set_size=1000), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("apt-fa-transfer"), included_in=LAND_BLOCKING_AND_C | Flow.REPRESENTATIVE | Flow.MAINNET),
    RunGroupConfig(key=RunGroupKey("apt-fa-transfer", executor_type="native"), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("account-generation"), included_in=LAND_BLOCKING_AND_C | Flow.REPRESENTATIVE | Flow.MAINNET),
    RunGroupConfig(key=RunGroupKey("account-generation", executor_type="native"), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("account-resource32-b"), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("modify-global-resource"), included_in=LAND_BLOCKING_AND_C | Flow.REPRESENTATIVE),
    RunGroupConfig(key=RunGroupKey("modify-global-resource", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("publish-package"), included_in=LAND_BLOCKING_AND_C | Flow.REPRESENTATIVE | Flow.MAINNET),
    RunGroupConfig(key=RunGroupKey("mix_publish_transfer"), key_extra=RunGroupKeyExtra(
        transaction_type_override="publish-package apt-fa-transfer",
        transaction_weights_override="1 500",
    ), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("batch100-transfer"), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("batch100-transfer", executor_type="native"), included_in=Flow.CONTINUOUS),

    RunGroupConfig(expected_tps=100, key=RunGroupKey("vector-picture40"), included_in=Flow(0), waived=True),
    RunGroupConfig(expected_tps=1000, key=RunGroupKey("vector-picture40", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow(0), waived=True),
    RunGroupConfig(key=RunGroupKey("vector-picture30k"), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("vector-picture30k", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("smart-table-picture30-k-with200-change"), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("smart-table-picture30-k-with200-change", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),
    # RunGroupConfig(expected_tps=10, key=RunGroupKey("smart-table-picture1-m-with256-change"), included_in=LAND_BLOCKING_AND_C),
    # RunGroupConfig(expected_tps=40, key=RunGroupKey("smart-table-picture1-m-with256-change", module_working_set_size=20), included_in=Flow.CONTINUOUS),

    RunGroupConfig(key=RunGroupKey("modify-global-resource-agg-v2"), included_in=Flow.AGG_V2 | LAND_BLOCKING_AND_C),
    RunGroupConfig(expected_tps=10000, key=RunGroupKey("modify-global-resource-agg-v2", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.AGG_V2, waived=True),
    RunGroupConfig(key=RunGroupKey("modify-global-flag-agg-v2"), included_in=Flow.AGG_V2 | Flow.CONTINUOUS),
    RunGroupConfig(expected_tps=10000, key=RunGroupKey("modify-global-flag-agg-v2", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.AGG_V2, waived=True),
    RunGroupConfig(key=RunGroupKey("modify-global-bounded-agg-v2"), included_in=Flow.AGG_V2 | Flow.CONTINUOUS),
    RunGroupConfig(expected_tps=10000, key=RunGroupKey("modify-global-bounded-agg-v2", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.AGG_V2, waived=True),
    RunGroupConfig(key=RunGroupKey("modify-global-milestone-agg-v2"), included_in=Flow.AGG_V2 | Flow.CONTINUOUS),

    RunGroupConfig(key=RunGroupKey("resource-groups-global-write-tag1-kb"), included_in=LAND_BLOCKING_AND_C | Flow.RESOURCE_GROUPS),
    RunGroupConfig(expected_tps=8000, key=RunGroupKey("resource-groups-global-write-tag1-kb", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.RESOURCE_GROUPS, waived=True),
    RunGroupConfig(key=RunGroupKey("resource-groups-global-write-and-read-tag1-kb"), included_in=Flow.CONTINUOUS | Flow.RESOURCE_GROUPS),
    RunGroupConfig(expected_tps=8000, key=RunGroupKey("resource-groups-global-write-and-read-tag1-kb", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.RESOURCE_GROUPS, waived=True),
    RunGroupConfig(key=RunGroupKey("resource-groups-sender-write-tag1-kb"), included_in=Flow.CONTINUOUS | Flow.RESOURCE_GROUPS),
    RunGroupConfig(expected_tps=8000, key=RunGroupKey("resource-groups-sender-write-tag1-kb", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.RESOURCE_GROUPS, waived=True),
    RunGroupConfig(key=RunGroupKey("resource-groups-sender-multi-change1-kb"), included_in=LAND_BLOCKING_AND_C | Flow.RESOURCE_GROUPS),
    RunGroupConfig(expected_tps=8000, key=RunGroupKey("resource-groups-sender-multi-change1-kb", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.RESOURCE_GROUPS, waived=True),

    RunGroupConfig(key=RunGroupKey("token-v1ft-mint-and-transfer"), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("token-v1ft-mint-and-transfer", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("token-v1nft-mint-and-transfer-sequential"), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("token-v1nft-mint-and-transfer-sequential", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),
    RunGroupConfig(expected_tps=1300, key=RunGroupKey("token-v1nft-mint-and-transfer-parallel"), included_in=Flow(0), waived=True),
    RunGroupConfig(expected_tps=5300, key=RunGroupKey("token-v1nft-mint-and-transfer-parallel", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow(0), waived=True),

    RunGroupConfig(key=RunGroupKey("coin-init-and-mint", module_working_set_size=1), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("coin-init-and-mint", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("fungible-asset-mint", module_working_set_size=1), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("fungible-asset-mint", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),

    # RunGroupConfig(expected_tps=1000, key=RunGroupKey("token-v1ft-mint-and-store"), included_in=Flow(0)),
    # RunGroupConfig(expected_tps=1000, key=RunGroupKey("token-v1nft-mint-and-store-sequential"), included_in=Flow(0)),
    # RunGroupConfig(expected_tps=1000, key=RunGroupKey("token-v1nft-mint-and-transfer-parallel"), included_in=Flow(0)),

    RunGroupConfig(key=RunGroupKey("no-op5-signers"), included_in=Flow.CONTINUOUS),

    RunGroupConfig(key=RunGroupKey("token-v2-ambassador-mint"), included_in=LAND_BLOCKING_AND_C | Flow.REPRESENTATIVE | Flow.MAINNET),
    RunGroupConfig(key=RunGroupKey("token-v2-ambassador-mint", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),

    RunGroupConfig(key=RunGroupKey("liquidity-pool-swap"), included_in=LAND_BLOCKING_AND_C | Flow.REPRESENTATIVE),
    RunGroupConfig(key=RunGroupKey("liquidity-pool-swap", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),

    RunGroupConfig(key=RunGroupKey("liquidity-pool-swap-stable"), included_in=Flow.CONTINUOUS),
    RunGroupConfig(key=RunGroupKey("liquidity-pool-swap-stable", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),

    RunGroupConfig(key=RunGroupKey("deserialize-u256"), included_in=Flow.CONTINUOUS),

    # fee payer sequentializes transactions today. in these tests module publisher is the fee payer, so larger number of modules tests throughput with multiple fee payers
    RunGroupConfig(key=RunGroupKey("no-op-fee-payer"), included_in=LAND_BLOCKING_AND_C),
    RunGroupConfig(key=RunGroupKey("no-op-fee-payer", module_working_set_size=DEFAULT_MODULE_WORKING_SET_SIZE), included_in=Flow.CONTINUOUS),

    RunGroupConfig(expected_tps=50000, key=RunGroupKey("coin_transfer_connected_components", executor_type="sharded"), key_extra=RunGroupKeyExtra(sharding_traffic_flags="--connected-tx-grps 5000", transaction_type_override=""), included_in=Flow.REPRESENTATIVE, waived=True),
    RunGroupConfig(expected_tps=50000, key=RunGroupKey("coin_transfer_hotspot", executor_type="sharded"), key_extra=RunGroupKeyExtra(sharding_traffic_flags="--hotspot-probability 0.8", transaction_type_override=""), included_in=Flow.REPRESENTATIVE, waived=True),

    # setting separately for previewnet, as we run on a different number of cores.
    RunGroupConfig(expected_tps=20000, key=RunGroupKey("apt-fa-transfer"), included_in=Flow.MAINNET_LARGE_DB),
    RunGroupConfig(expected_tps=15000, key=RunGroupKey("account-generation"), included_in=Flow.MAINNET_LARGE_DB),
    RunGroupConfig(expected_tps=60, key=RunGroupKey("publish-package"), included_in=Flow.MAINNET_LARGE_DB),
    RunGroupConfig(expected_tps=6800, key=RunGroupKey("token-v2-ambassador-mint"), included_in=Flow.MAINNET_LARGE_DB),
    # RunGroupConfig(expected_tps=17000 if NUM_ACCOUNTS < 5000000 else 28000, key=RunGroupKey("coin_transfer_connected_components", executor_type="sharded"), key_extra=RunGroupKeyExtra(sharding_traffic_flags="--connected-tx-grps 5000", transaction_type_override=""), included_in=Flow.MAINNET | Flow.MAINNET_LARGE_DB, waived=True),
    # RunGroupConfig(expected_tps=27000 if NUM_ACCOUNTS < 5000000 else 23000, key=RunGroupKey("coin_transfer_hotspot", executor_type="sharded"), key_extra=RunGroupKeyExtra(sharding_traffic_flags="--hotspot-probability 0.8", transaction_type_override=""), included_in=Flow.MAINNET | Flow.MAINNET_LARGE_DB, waived=True),

    RunGroupConfig(expected_tps=1000, key=RunGroupKey("simple-script"), included_in=LAND_BLOCKING_AND_C, waived=True),
]
# fmt: on

# Run the single node with performance optimizations enabled
target_directory = "execution/executor-benchmark/src"


class CmdExecutionError(Exception):
    def __init__(self, return_code, output):
        super().__init__(f"CmdExecutionError with {return_code}")
        self.return_code = return_code
        self.output = output


def execute_command(command):
    print(f"Executing command:\n\t{command}\nand waiting for it to finish...")
    result = []
    with Popen(
        command,
        shell=True,
        text=True,
        stdout=PIPE,
        bufsize=1,
        universal_newlines=True,
    ) as p:
        # stream to output while command is executing
        if p.stdout is not None:
            for line in p.stdout:
                if not HIDE_OUTPUT:
                    print(line, end="")
                result.append(line)

    # return the full output in the end for postprocessing
    full_result = "\n".join(result)

    if p.returncode != 0:
        if HIDE_OUTPUT:
            print(full_result)
        raise CmdExecutionError(p.returncode, full_result)

    if " ERROR " in full_result:
        print("ERROR log line in execution")
        if HIDE_OUTPUT:
            print(full_result)
        exit(1)

    return full_result


@dataclass
class RunResults:
    tps: float
    gps: float
    effective_gps: float
    io_gps: float
    execution_gps: float
    gpt: float
    storage_fee_pt: float
    output_bps: float
    fraction_in_execution: float
    fraction_of_execution_in_vm: float
    fraction_in_commit: float


@dataclass
class RunGroupInstance:
    key: RunGroupKey
    single_node_result: RunResults
    number_of_threads_results: Mapping[int, RunResults]
    block_size: int
    expected_tps: float


@dataclass
class CalibrationData:
    expected_tps: float
    count: int
    min_ratio: float
    max_ratio: float


@dataclass
class Criteria:
    expected_tps: float
    min_tps: float
    min_warn_tps: float
    max_tps: float
    max_warn_tps: float


def get_only(values):
    assert len(values) == 1, "Multiple values parsed: " + str(values)
    return values[0]


def extract_run_results(
    output: str, prefix: str, create_db: bool = False
) -> RunResults:
    if create_db:
        tps = float(
            get_only(
                re.findall(
                    r"Overall TPS: create_db: account creation: (\d+\.?\d*) txn/s",
                    output,
                )
            )
        )
        gps = 0
        effective_gps = 0
        io_gps = 0
        execution_gps = 0
        gpt = 0
        storage_fee_pt = 0
        output_bps = 0
        fraction_in_execution = 0
        fraction_of_execution_in_vm = 0
        fraction_in_commit = 0
    else:
        tps = float(get_only(re.findall(prefix + r" TPS: (\d+\.?\d*) txn/s", output)))
        gps = float(get_only(re.findall(prefix + r" GPS: (\d+\.?\d*) gas/s", output)))
        effective_gps = float(
            get_only(re.findall(prefix + r" effectiveGPS: (\d+\.?\d*) gas/s", output))
        )
        io_gps = float(
            get_only(re.findall(prefix + r" ioGPS: (\d+\.?\d*) gas/s", output))
        )
        execution_gps = float(
            get_only(re.findall(prefix + r" executionGPS: (\d+\.?\d*) gas/s", output))
        )
        gpt = float(get_only(re.findall(prefix + r" GPT: (\d+\.?\d*) gas/txn", output)))
        storage_fee_pt = float(
            get_only(
                re.findall(prefix + r" Storage fee: (\-?\d+\.?\d*) octas/txn", output)
            )
        )

        output_bps = float(
            get_only(re.findall(prefix + r" output: (\d+\.?\d*) bytes/s", output))
        )
        fraction_in_execution = float(
            re.findall(
                prefix + r" fraction of total: (\d+\.?\d*) in execution", output
            )[-1]
        )
        fraction_of_execution_in_vm = float(
            re.findall(prefix + r" fraction of execution (\d+\.?\d*) in VM", output)[-1]
        )
        fraction_in_commit = float(
            re.findall(prefix + r" fraction of total: (\d+\.?\d*) in commit", output)[
                -1
            ]
        )

    return RunResults(
        tps=tps,
        gps=gps,
        effective_gps=effective_gps,
        io_gps=io_gps,
        execution_gps=execution_gps,
        gpt=gpt,
        storage_fee_pt=storage_fee_pt,
        output_bps=output_bps,
        fraction_in_execution=fraction_in_execution,
        fraction_of_execution_in_vm=fraction_of_execution_in_vm,
        fraction_in_commit=fraction_in_commit,
    )


def print_table(
    results: Sequence[RunGroupInstance],
    by_levels: bool,
    single_field: Optional[Tuple[str, Callable[[RunResults], Any]]],
    number_of_execution_threads=EXECUTION_ONLY_NUMBER_OF_THREADS,
):
    headers = [
        "transaction_type",
        "module_working_set",
        "executor",
        "block_size",
        "expected t/s",
    ]
    if by_levels:
        headers.extend(
            [f"exe_only {num_threads}" for num_threads in number_of_execution_threads]
        )
        assert single_field is not None

    if single_field is not None:
        field_name, _ = single_field
        headers.append(field_name)
    else:
        headers.extend(
            [
                "t/s",
                "exe/total",
                "vm/exe",
                "commit/total",
                "g/s",
                "eff g/s",
                "io g/s",
                "exe g/s",
                "g/t",
                "fee/t",
                "out B/s",
            ]
        )

    rows = []
    for result in results:
        row = [
            result.key.transaction_type,
            result.key.module_working_set_size,
            result.key.executor_type,
            result.block_size,
            result.expected_tps,
        ]
        if by_levels:
            if single_field is not None:
                _, field_getter = single_field
                for num_threads in number_of_execution_threads:
                    if num_threads in result.number_of_threads_results:
                        row.append(
                            field_getter(result.number_of_threads_results[num_threads])
                        )
                    else:
                        row.append("-")

        if single_field is not None:
            _, field_getter = single_field
            row.append(field_getter(result.single_node_result))
        else:
            row.append(int(round(result.single_node_result.tps)))
            row.append(round(result.single_node_result.fraction_in_execution, 3))
            row.append(round(result.single_node_result.fraction_of_execution_in_vm, 3))
            row.append(round(result.single_node_result.fraction_in_commit, 3))
            row.append(int(round(result.single_node_result.gps)))
            row.append(int(round(result.single_node_result.effective_gps)))
            row.append(int(round(result.single_node_result.io_gps)))
            row.append(int(round(result.single_node_result.execution_gps)))
            row.append(int(round(result.single_node_result.gpt)))
            row.append(int(round(result.single_node_result.storage_fee_pt)))
            row.append(int(round(result.single_node_result.output_bps)))
        rows.append(row)

    print(tabulate(rows, headers=headers))


errors = []
warnings = []

with tempfile.TemporaryDirectory() as tmpdirname:
    move_e2e_benchmark_failed = False
    if not SKIP_MOVE_E2E:
        execute_command(f"cargo build {BUILD_FLAG} --package aptos-move-e2e-benchmark")
        try:
            execute_command(f"RUST_BACKTRACE=1 {BUILD_FOLDER}/aptos-move-e2e-benchmark")
        except:
            # for land-blocking (i.e. on PR), fail immediately, for speedy response.
            # Otherwise run all tests, and fail in the end.
            if SELECTED_FLOW == Flow.LAND_BLOCKING:
                print("Move E2E benchmark failed, exiting")
                exit(1)
            move_e2e_benchmark_failed = True

    calibrated_expected_tps = {
        RunGroupKey(
            transaction_type=parts[0],
            module_working_set_size=int(parts[1]),
            executor_type=parts[2],
        ): CalibrationData(
            expected_tps=float(parts[CALIBRATED_TPS_INDEX]),
            count=int(parts[CALIBRATED_COUNT_INDEX]),
            min_ratio=float(parts[CALIBRATED_MIN_RATIO_INDEX]),
            max_ratio=float(parts[CALIBRATED_MAX_RATIO_INDEX]),
        )
        for line in CALIBRATION.split("\n")
        if len(
            parts := [
                part for part in line.strip().split(CALIBRATION_SEPARATOR) if part
            ]
        )
        >= 1
    }
    print(calibrated_expected_tps)

    execute_command(f"cargo build {BUILD_FLAG} --package aptos-executor-benchmark")
    print(f"Warmup - creating DB with {NUM_ACCOUNTS} accounts")
    create_db_command = f"RUST_BACKTRACE=1 {BUILD_FOLDER}/aptos-executor-benchmark --block-size {MAX_BLOCK_SIZE} --execution-threads {NUMBER_OF_EXECUTION_THREADS} {DB_CONFIG_FLAGS} {DB_PRUNER_FLAGS} create-db {FEATURE_FLAGS} --data-dir {tmpdirname}/db --num-accounts {NUM_ACCOUNTS}"
    output = execute_command(create_db_command)

    results = []

    results.append(
        RunGroupInstance(
            key=RunGroupKey("warmup"),
            single_node_result=extract_run_results(output, "Overall", create_db=True),
            number_of_threads_results={},
            block_size=MAX_BLOCK_SIZE,
            expected_tps=0,
        )
    )

    for (
        test_index,
        test,
    ) in enumerate(TESTS):
        if SELECTED_FLOW not in test.included_in:
            continue

        if SKIP_NATIVE and test.key.executor_type == "native":
            continue

        if test.expected_tps is not None:
            print(f"WARNING: using uncalibrated TPS for {test.key}")
            criteria = Criteria(
                expected_tps=test.expected_tps,
                min_tps=test.expected_tps * NOISE_LOWER_LIMIT,
                min_warn_tps=test.expected_tps * NOISE_LOWER_LIMIT_WARN,
                max_tps=test.expected_tps * NOISE_UPPER_LIMIT,
                max_warn_tps=test.expected_tps * NOISE_UPPER_LIMIT_WARN,
            )
        else:
            assert test.key in calibrated_expected_tps, test
            cur_calibration = calibrated_expected_tps[test.key]
            criteria = Criteria(
                expected_tps=cur_calibration.expected_tps,
                min_tps=cur_calibration.expected_tps
                * (
                    1
                    - (1 - cur_calibration.min_ratio)
                    * (1 + 10.0 / cur_calibration.count)
                    - 1.0 / cur_calibration.count
                ),
                min_warn_tps=cur_calibration.expected_tps
                * pow(cur_calibration.min_ratio, 0.8),
                max_tps=cur_calibration.expected_tps
                * (
                    1
                    + (cur_calibration.max_ratio - 1)
                    * (1 + 10.0 / cur_calibration.count)
                    + 1.0 / cur_calibration.count
                ),
                max_warn_tps=cur_calibration.expected_tps
                * pow(cur_calibration.max_ratio, 0.8),
            )

        cur_block_size = int(min([criteria.expected_tps, MAX_BLOCK_SIZE]))

        print(f"Testing {test.key}")
        if test.key_extra.transaction_type_override == "":
            workload_args_str = ""
        else:
            transaction_type_list = (
                test.key_extra.transaction_type_override or test.key.transaction_type
            )
            transaction_weights_list = (
                test.key_extra.transaction_weights_override or "1"
            )
            workload_args_str = f"--transaction-type {transaction_type_list} --transaction-weights {transaction_weights_list}"

        sharding_traffic_flags = test.key_extra.sharding_traffic_flags or ""

        if test.key.executor_type == "VM":
            executor_type_str = "--transactions-per-sender 1"
        elif test.key.executor_type == "native":
            executor_type_str = "--use-native-executor --transactions-per-sender 1"
        elif test.key.executor_type == "sharded":
            executor_type_str = f"--num-executor-shards {NUMBER_OF_EXECUTION_THREADS} {sharding_traffic_flags}"
        else:
            raise Exception(f"executor type not supported {test.key.executor_type}")
        txn_emitter_prefix_str = "" if NUM_BLOCKS > 200 else " --generate-then-execute"

        ADDITIONAL_DST_POOL_ACCOUNTS = 2 * MAX_BLOCK_SIZE * NUM_BLOCKS

        common_command_suffix = f"{executor_type_str} {txn_emitter_prefix_str} --block-size {cur_block_size} {DB_CONFIG_FLAGS} {DB_PRUNER_FLAGS} run-executor {FEATURE_FLAGS} {workload_args_str} --module-working-set-size {test.key.module_working_set_size} --main-signer-accounts {MAIN_SIGNER_ACCOUNTS} --additional-dst-pool-accounts {ADDITIONAL_DST_POOL_ACCOUNTS} --data-dir {tmpdirname}/db  --checkpoint-dir {tmpdirname}/cp"

        number_of_threads_results = {}

        for execution_threads in EXECUTION_ONLY_NUMBER_OF_THREADS:
            test_db_command = f"RUST_BACKTRACE=1 {BUILD_FOLDER}/aptos-executor-benchmark --execution-threads {execution_threads} --skip-commit {common_command_suffix} --blocks {NUM_BLOCKS_DETAILED}"
            output = execute_command(test_db_command)

            number_of_threads_results[execution_threads] = extract_run_results(
                output, "Overall execution"
            )

        test_db_command = f"RUST_BACKTRACE=1 {BUILD_FOLDER}/aptos-executor-benchmark --execution-threads {NUMBER_OF_EXECUTION_THREADS} {common_command_suffix} --blocks {NUM_BLOCKS}"
        output = execute_command(test_db_command)

        single_node_result = extract_run_results(output, "Overall")
        stage_node_results = []

        for i in itertools.count():
            prefix = f"Staged execution: stage {i}:"
            if prefix in output:
                stage_node_results.append((i, extract_run_results(output, prefix)))
            else:
                break

        results.append(
            RunGroupInstance(
                key=test.key,
                single_node_result=single_node_result,
                number_of_threads_results=number_of_threads_results,
                block_size=cur_block_size,
                expected_tps=criteria.expected_tps,
            )
        )

        for stage, stage_node_result in stage_node_results:
            results.append(
                RunGroupInstance(
                    key=RunGroupKey(
                        transaction_type=test.key.transaction_type
                        + f" [stage {stage}]",
                        module_working_set_size=test.key.module_working_set_size,
                        executor_type=test.key.executor_type,
                    ),
                    single_node_result=stage_node_result,
                    number_of_threads_results=number_of_threads_results,
                    block_size=cur_block_size,
                    expected_tps=criteria.expected_tps,
                )
            )

        # line to be able to aggreate and visualize in Humio
        print(
            json.dumps(
                {
                    "grep": "grep_json_single_node_perf",
                    "source": SOURCE,
                    "runner_name": RUNNER_NAME,
                    "transaction_type": test.key.transaction_type,
                    "module_working_set_size": test.key.module_working_set_size,
                    "executor_type": test.key.executor_type,
                    "block_size": cur_block_size,
                    "execution_threads": NUMBER_OF_EXECUTION_THREADS,
                    "warmup_num_accounts": NUM_ACCOUNTS,
                    "expected_tps": criteria.expected_tps,
                    "expected_min_tps": criteria.min_tps,
                    "expected_max_tps": criteria.max_tps,
                    "waived": test.waived,
                    "tps": single_node_result.tps,
                    "gps": single_node_result.gps,
                    "gpt": single_node_result.gpt,
                    "code_perf_version": CODE_PERF_VERSION,
                    "flow": str(SELECTED_FLOW),
                    "test_index": test_index,
                }
            )
        )

        if not HIDE_OUTPUT:
            print_table(
                results,
                by_levels=True,
                single_field=("t/s", lambda r: int(round(r.tps))),
            )
            print_table(
                results,
                by_levels=True,
                single_field=("g/s", lambda r: int(round(r.gps))),
            )
            print_table(
                results,
                by_levels=False,
                single_field=("gas/txn", lambda r: int(round(r.gpt))),
            )
            print_table(
                results,
                by_levels=False,
                single_field=(
                    "storage fee/txn",
                    lambda r: int(round(r.storage_fee_pt)),
                ),
            )
            print_table(
                results,
                by_levels=True,
                single_field=("exe/total", lambda r: round(r.fraction_in_execution, 3)),
            )
            print_table(
                results,
                by_levels=True,
                single_field=(
                    "vm/exe",
                    lambda r: round(r.fraction_of_execution_in_vm, 3),
                ),
            )
            print_table(results, by_levels=False, single_field=None)

        if single_node_result.tps < criteria.min_tps:
            text = f"regression detected {single_node_result.tps}, expected median {criteria.expected_tps}, threshold: {criteria.min_tps}), {test.key} didn't meet TPS requirements"
            if not test.waived:
                errors.append(text)
            else:
                warnings.append(text)
        elif single_node_result.tps < criteria.min_warn_tps:
            text = f"potential (but within normal noise) regression detected {single_node_result.tps}, expected median {criteria.expected_tps}, threshold: {criteria.min_warn_tps}), {test.key} didn't meet TPS requirements"
            warnings.append(text)
        elif (
            not SKIP_PERF_IMPROVEMENT_NOTICE
            and single_node_result.tps > criteria.max_tps
        ):
            text = f"perf improvement detected {single_node_result.tps}, expected median {criteria.expected_tps}, threshold: {criteria.max_tps}), {test.key} exceeded TPS requirements, increase TPS requirements to match new baseline"
            if not test.waived:
                errors.append(text)
            else:
                warnings.append(text)
        elif (
            not SKIP_PERF_IMPROVEMENT_NOTICE
            and single_node_result.tps > criteria.max_warn_tps
        ):
            text = f"potential (but within normal noise) perf improvement detected {single_node_result.tps}, expected median {criteria.expected_tps}, threshold: {criteria.max_warn_tps}), {test.key} exceeded TPS requirements, increase TPS requirements to match new baseline"
            warnings.append(text)

if HIDE_OUTPUT:
    print_table(results, by_levels=False, single_field=None)

if warnings:
    print("Warnings: ")
    print("\n".join(warnings))
    print("You can run again to see if it is noise, or consistent.")

if errors:
    print("Errors: ")
    print("\n".join(errors))
    print(
        """If you expect your PR to change the performance, you need to recalibrate the values.
To do so, you should run the test on your branch 6 times
(https://github.com/aptos-labs/aptos-core/actions/workflows/workflow-run-execution-performance.yaml ; remember to select CONTINUOUS).
Then go to Humio calibration link (https://gist.github.com/igor-aptos/7b12ca28de03894cddda8e415f37889e),
update it to your branch, and export values as CSV, and then open and copy values inside
testsuite/single_node_performance.py testsuite), and add Blockchain oncall as the reviewer.
"""
    )
    exit(1)

if move_e2e_benchmark_failed:
    print(
        "Move e2e benchmark failed, failing the job. See logs at the beginning for more details."
    )
    exit(1)

exit(0)
