/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief SFC EF_VI API Test Suite epilogue.
 *
 * @author Damir Mansurov  <Damir.Mansurov@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

/** Logging subsystem entity name */
#define TE_TEST_NAME    "epilogue"

#include "efvi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_SUCCESS;
cleanup:
    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */

