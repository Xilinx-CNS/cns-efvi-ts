/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * EF_VI API Test Suite
 * Reliability EF_VI API in Normal Use
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

/** @page usecases-driver_open_close driver open/close operations
 *
 * @objective Test on reliability of the @b driver open/close operations
 *            on EF_VI API.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/driver_open_close"

#include "efvi_test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    rpc_ef_driver_handle    dh;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);

    TEST_STEP("Open ef_driver handle");
    rpc_ef_driver_open(pco_iut, &dh);

    TEST_STEP("Close ef_driver handle");
    rpc_ef_driver_close(pco_iut, dh);

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
