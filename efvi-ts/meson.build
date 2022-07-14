# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved.
project('efvi-ts', 'c', version : '1.0.0')

te_path = get_option('te_path')
te_libdir = get_option('te_libdir')
add_project_arguments(get_option('te_cflags').split(), language: 'c')
add_project_link_arguments(get_option('te_ldflags').split(), language: 'c')

cc = meson.get_compiler('c')

te_tests_info_sh = find_program(join_paths(te_path, 'te_tests_info.sh'))

test_deps = [ dependency('threads') ]

# The line below would produce empty dependencies on systems
# having no tirpc - it is not a problem.
dep_tirpc = dependency('libtirpc', required: false)

test_deps += dep_tirpc

te_libs = [
    'confapi',
    'conf_oid',
    'logger_core',
    'logger_ten',
    'tapi',
    'tapi_env',
    'tapi_rpc',
    'tapi_serial',
    'tools',
    'rcfapi',
    'rpc_types',
    'rcfrpc',
    'rpcxdr'
]

foreach lib : te_libs
    test_deps += dependency('te-' + lib)
endforeach

onload_tslib_dir = run_command('sh', '-c', 'echo ${SFC_ONLOAD_LIB}').stdout().strip()
message('Using SFC_ONLOAD_LIB: ' + onload_tslib_dir)

lib_dir = include_directories(
    onload_tslib_dir,
    '../talib_efvi_ts/include',
    'lib',
)

subdir('lib')

test_deps += declare_dependency(include_directories: lib_dir,
                                link_with: ts_efvi_lib)

tests = [
    'prologue',
    'epilogue',
]

package_dir = 'efvi-ts'
package_tests_c = []

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data([ 'mainpage.dox', 'package.xml' ],
             install_dir: package_dir)

packages = [
    'usecases',
]

mydir = package_dir
foreach package : packages
    package_dir = join_paths(mydir, package)
    package_tests_c = []
    subdir(package)
endforeach
