# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved.
sources = [
    'efvi_rpc.c',
    'efvi_ts.c',
    join_paths(onload_tslib_dir, 'lib-ts.c'),
]

ts_efvi_lib = static_library('ts_efvi', sources,
                             include_directories: lib_dir,
                             dependencies: dep_tirpc)
