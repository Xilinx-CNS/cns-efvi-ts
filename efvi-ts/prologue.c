/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief SFC EF_VI API Test Suite prologue.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

/** Logging subsystem entity name */
#define TE_TEST_NAME    "prologue"

#include "efvi_test.h"
#include "tapi_network.h"
#include "lib-ts.h"

int
main(int argc, char **argv)
{
    rcf_rpc_server *pco_iut;
    rcf_rpc_server *pco_tst;

    char           *st_no_ip6 = getenv("ST_NO_IP6");

/* Redefine as empty to avoid environment processing here */
#undef TEST_START_SPECIFIC
#define TEST_START_SPECIFIC
    TEST_START;
    tapi_env_init(&env);

    TEST_STEP("Set console loglevel in accordance with @b ST_CONSOLE_LOGLEVEL");
    libts_init_console_loglevel();

    TEST_STEP("Make sure @b PATH includes system commands locations on all "
              "test agents");
    libts_fix_tas_path_env();

    TEST_STEP("Restart existing RPC servers after the PATH is updated on test "
              "agents");
    CHECK_RC(rcf_rpc_servers_restart_all());

    TEST_STEP("Reserve resources, set IP addresses and static ARP "
              "(if required)");
    tapi_network_setup(st_no_ip6 == NULL || *st_no_ip6 == '\0');

    TEST_STEP("Set environment variables specified in /local/env on "
              "corresponding test agents");
    CHECK_RC(tapi_cfg_env_local_to_agent());

    TEST_STEP("Copy API libraries specified in /local/socklib instances to "
              "test agents");
    if ((rc = libts_copy_socklibs()) != 0)
        TEST_FAIL("Processing of /local:*/socklib: failed: %r", rc);

    TEST_STEP("Sleep according to prologue_sleep value");
    if (TEST_BEHAVIOUR(prologue_sleep) > 0)
        SLEEP(test_behaviour_storage.prologue_sleep);

    TEST_STEP("Synchronize Configurator database");
    CHECK_RC(rc = cfg_synchronize("/:", TRUE));

    TEST_START_ENV;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_STEP("Flush neighbours tables in all hosts to avoid invalid "
              "neighbours entry");
    CHECK_RC(tapi_neight_flush_ta(pco_tst));
    CHECK_RC(tapi_neight_flush_ta(pco_iut));

    /*
     * Sometimes after rebooting the host ipmi/conserver stops showing
     * anything. This problem is solved if you send "enter" to console.
     * For more information see Bug 9831.
     */
    TEST_STEP("impi/conserver: send \"enter\" to console");
    libts_send_enter2serial_console(SERIAL_LOG_PARSER_AGENT, "rpcs_serial",
                                    SERIAL_LOG_PARSER_CONSOLE_NAME);

    TEST_STEP("Print a tree of configurator objects/instances");
    CHECK_RC(rc = cfg_tree_print(NULL, TE_LL_RING, "/:"));

    TEST_SUCCESS;
cleanup:

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
