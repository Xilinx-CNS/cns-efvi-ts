#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved.
#
# Helper script to run Test Environment for the Test Suite
#
# Author: Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
#

set -e

declare -a RUN_OPTS
declare -a MY_OPTS
declare -a OOL_SET

# The efvi-ts suite supports a limited set of ool.config.* options.
declare -A OOL_SUPPORT
OOL_SUPPORT["fw_full_featured"]=true
OOL_SUPPORT["fw_low_latency"]=true

do_item=true
ignore_zeroconf=false
cfg=
is_cmod=false

pushd "$(dirname "$(which "$0")")" >/dev/null
RUNDIR="$(pwd -P)"
popd >/dev/null

test "$(basename $RUNDIR)" = "scripts" && RUNDIR="${RUNDIR}/.."
test -e "${RUNDIR}/scripts/guess.sh" && source "${RUNDIR}/scripts/guess.sh"

source ${SF_TS_CONFDIR}/scripts/lib.run

test -z "${TE_TS_EFVI}" -a -d "${RUNDIR}/efvi-ts" && \
    export TE_TS_EFVI="${RUNDIR}/efvi-ts"

test -z "${EFVI_TS_LIBDIR}" -a -d "${RUNDIR}/talib_efvi_ts" && \
    export EFVI_TS_LIBDIR="${RUNDIR}/talib_efvi_ts"

usage() {
cat <<EOF
USAGE: run.sh [run.sh options] [dispatcher.sh options]
Options:
  --cfg=<CFG>               Configuration to be used
  --ool=<OOL CFG>           OOL product configuration file
  --ignore-zeroconf         To suppress ZeroConf checking

EOF
${TE_BASE}/dispatcher.sh --help
exit 1
}

RUN_OPTS+=("--trc-comparison=normalised")
RUN_OPTS+=("--build-meson")
RUN_OPTS+=("--tester-only-req-logues")

while test -n "$1" ; do
    case $1 in
        --help) usage ;;
        --ignore-zeroconf) ignore_zeroconf="true" ;;
        --no-item) do_item=false ;;
        --ool=*) OOL_SET+=("${1#--ool=}") ;;
        --cfg=cmod-x3sim-*)
            is_cmod=true
            ;;&
        --cfg=*)
            cfg=${1#--cfg=}

            # Use cfg as hostame
            ${is_cmod} || hostname="$cfg"

            RUN_OPTS+=("--opts=run/$cfg")
            if $do_item ; then
                ${is_cmod} || take_items "$cfg"
            fi
            ;;
        *)  RUN_OPTS+=("$1") ;;
    esac
    shift 1
done

RUN_OPTS+=("--opts=opts.ts")

ool_not_supported=
for o in ${OOL_SET[@]} ; do
    if test "${OOL_SUPPORT[${o}]}" = "true" ; then
        RUN_OPTS+=("--script=ool/config/$o")
    else
        ool_not_supported+=" $o"
    fi
done
if test -n "$ool_not_supported" ; then
    echo "ERROR: unsupported ool option(s):${ool_not_supported}" >&2
    exit 1
fi

if test -z "${TE_BUILD}" ; then
    if test "${RUNDIR}" = "$(pwd -P)" ; then
        TE_BUILD="$(pwd -P)/build"
        mkdir -p build
    else
        TE_BUILD="$(pwd -P)"
    fi
    export TE_BUILD
fi

MY_OPTS+=("--conf-dirs=\"${RUNDIR}/conf:${SF_TS_CONFDIR}\"")
MY_OPTS+=("--trc-html=trc-report.html")
MY_OPTS+=("--trc-no-total")
MY_OPTS+=("--trc-no-unspec")
MY_OPTS+=("--trc-key2html=${SF_TS_CONFDIR}/trc.key2html")
MY_OPTS+=("--trc-db=${RUNDIR}/trc/top.xml")

# the cmod-x3sim-* configurations are care about names of interfaces
if ! $is_cmod ; then
    export_te_workspace_make_dirs "${SF_TS_CONFDIR}/env/$hostname"
    hosts=$(cat ${SF_TS_CONFDIR}/env/$hostname | egrep "(TE_IUT=|TE_TST[0-9]*=)" | sed "s/.*=//")
fi

if ! $ignore_zeroconf ; then
    for curr_host in ${hosts}; do
        [ -n "`ssh $curr_host /sbin/route 2>/dev/null | grep ^link-local`" ] || continue
        echo "ZEROCONF is enabled on $curr_host. Use --ignore-zeroconf to suppress warning." >&2
        echo "Add 'NOZEROCONF=yes' line to /etc/sysconfig/network to disable ZEROCONF." >&2
        exit 1
    done
fi

if ! $is_cmod ; then
    export_cmdclient $hostname

    # Note: firmware variants (full/low) applicable for sfc only
    iut_ifs=( $(get_sfx_ifs $hostname sfc "") )
    export_iut_fw_version $hostname ${iut_ifs[0]}
fi
OOL_SET=$(fw_var_consistency $OOL_SET) || exit 1

RESULT=0
eval "${TE_BASE}/dispatcher.sh ${MY_OPTS[@]} ${RUN_OPTS[@]}" || RESULT=$?

if test ${RESULT} -ne 0 ; then
    echo FAIL
    echo ""
fi

echo -ne "\a"
exit ${RESULT}
