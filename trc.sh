# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved.
export TRC_DB=top.xml
[[ "$SF_TS_CONFDIR" = "" ]] && echo "Env SF_TS_CONFDIR must be specified" >&2 && exit 1
. $TE_BASE/scripts/trc.sh  --key2html=$SF_TS_CONFDIR/trc.key2html $@
