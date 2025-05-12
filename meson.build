# AIDE (Advanced Intrusion Detection Environment)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

project(
    'aide',
    'c',
    version: '0.17.4',
    license: 'GPL-2.0-or-later',
    default_options: ['c_std=gnu99', 'warning_level=1'],
)

cc = meson.get_compiler('c')

# Required dependencies
pthread_dep = dependency('threads', required: true)
m_dep = cc.find_library('m', required: true)
pcre2_dep = dependency('libpcre2-8', required: true)

# Optional dependencies
audit_dep = dependency('audit', required: get_option('audit'))
capabilities_dep = dependency('libcap', required: get_option('capabilities'))
curl_dep = dependency('libcurl', required: get_option('curl'))
e2fsattrs_dep = dependency('e2p', required: get_option('e2fsattrs'))
posix_acl_dep = dependency('libacl', required: get_option('posix_acl'))
selinux_dep = dependency('libselinux', required: get_option('selinux'))
xattr_dep = dependency('libattr', required: get_option('xattr'))
zlib_dep = dependency('zlib', required: get_option('zlib'))
check_dep = dependency('check', required: get_option('check'))

nettle_dep = dependency('nettle', required: get_option('nettle'))
gcrypt_dep = dependency('libgcrypt', required: get_option('gcrypt'))

# Configure yacc/bison and lex/flex
yacc = find_program('bison', 'yacc')
lex = find_program('flex', 'lex')

yacc_gen = generator(
    yacc,
    output: ['@BASENAME@.c', '@BASENAME@.h'],
    arguments: [
        '-d',
        '-Wno-yacc',
        '-Wall',
        '-Werror',
        '-p', 'conf',
        '--output=@OUTPUT0@',
        '@INPUT@',
    ],
)

lex_gen = generator(
    lex,
    output: '@BASENAME@.c',
    arguments: ['-o', '@OUTPUT@', '-Pconf', '@INPUT@'],
)

conf_yacc = yacc_gen.process('src/conf_yacc.y')
conf_lex = lex_gen.process('src/conf_lex.l')

aide_deps = [
    m_dep,
    pcre2_dep,
    pthread_dep,
]

aide_compile_options = ''
aide_config = configuration_data()

if (
    gcrypt_dep.found()
    and nettle_dep.found()
    and get_option('gcrypt').auto()
    and get_option('nettle').auto()
)
    message('Found both libgcrypt and nettle. Using gcrypt...')
    aide_deps += gcrypt_dep
    aide_compile_options += 'use Nettle crypto library: no\\n'
    aide_compile_options += 'use libgcrypt crypto library: yes\\n'
    aide_config.set('WITH_GCRYPT', 1)

elif gcrypt_dep.found()
    aide_deps += gcrypt_dep
    aide_compile_options += 'use Nettle crypto library: no\\n'
    aide_compile_options += 'use libgcrypt crypto library: yes\\n'
    aide_config.set('WITH_GCRYPT', 1)

elif nettle_dep.found()
    aide_deps += nettle_dep
    aide_compile_options += 'use Nettle crypto library: yes\\n'
    aide_compile_options += 'use libgcrypt crypto library: no\\n'
    aide_config.set('WITH_NETTLE', 1)
else
    error('AIDE requires either libgcrypt or nettle for hashsum calculation.')
endif

deps_map = [
    ['audit', get_option('audit'), ['WITH_AUDIT']],
    ['libcap', get_option('capabilities'), ['WITH_CAPABILITIES']],
    ['libcurl', get_option('curl'), ['WITH_CURL']],
    ['e2p', get_option('e2fsattrs'), ['WITH_E2FSATTRS']],
    ['libacl', get_option('posix_acl'), ['WITH_ACL', 'WITH_POSIX_ACL']],
    ['libselinux', get_option('selinux'), ['WITH_SELINUX']],
    ['libattr', get_option('xattr'), ['WITH_XATTR']],
    ['zlib', get_option('zlib'), ['WITH_ZLIB']],
]
 
foreach entry : deps_map
    dep_name = entry[0]
    opt = entry[1]
    defines = entry[2]
    dep = dependency(dep_name, required: opt)
    if dep.found()
        aide_deps += dep
        aide_compile_options += 'use ' + dep_name + ': yes\\n'
        foreach d : defines
            aide_config.set(d, 1)
        endforeach
    else
        aide_compile_options += 'use ' + dep_name + ': no\\n'
    endif
endforeach

# enable fstype on linux
if get_option('fstype').allowed() and (host_machine.system() == 'linux')
    aide_config.set('HAVE_FSTYPE', 1)
endif

aide_config.set('AIDEVERSION', '"' + meson.project_version() + '"')
aide_config.set('AIDECOMPILEOPTIONS', '"' + aide_compile_options + '"')
aide_config.set('AIDE_IDENT', '"' + get_option('syslog_ident') + '"')
aide_config.set('AIDE_SYSLOG_PRIORITY', get_option('syslog_priority'))
aide_config.set('AIDE_LOGOPT', get_option('syslog_logopt'))
aide_config.set('AIDE_SYSLOG_FACILITY', get_option('syslog_facility'))

# Headers
foreach h : ['sys/prctl.h', 'syslog.h', 'inttypes.h', 'fcntl.h', 'ctype.h']
    if cc.has_header(h)
        aide_config.set('HAVE_' + h.replace('.h', '').underscorify().to_upper(), 1)
    endif
endforeach

guarded_functions = [
    ['strnstr', 'HAVE_STRNSTR'],
    ['strnlen', 'HAVE_STRNLEN'],
    ['syslog_facility_lookup', 'HAVE_SYSLOG'],
    ['ftruncate', 'HAVE_FTRUNCATE'],
    ['stricmp', 'HAVE_STRICMP'],
]

foreach entry : guarded_functions
    func = entry[0]
    define = entry[1]
    if cc.has_function(func)
        aide_config.set(define, 1)
    endif
endforeach

conf_h = configure_file(output: 'config.h', configuration: aide_config)

# Core source files
aide_sources = [
    'include/aide.h',
    'include/attributes.h',
    'include/base64.h',
    'include/be.h',
    'include/commandconf.h',
    'include/conf_ast.h',
    'include/conf_eval.h',
    'include/conf_lex.h',
    'include/db.h',
    'include/db_config.h',
    'include/db_disk.h',
    'include/db_file.h',
    'include/db_line.h',
    'include/db_list.h',
    'include/do_md.h',
    'include/errorcodes.h',
    'include/file.h',
    'include/gen_list.h',
    'include/getopt.h',
    'include/hashsum.h',
    'include/list.h',
    'include/locale-aide.h',
    'include/log.h',
    'include/md.h',
    'include/progress.h',
    'include/queue.h',
    'include/report.h',
    'include/report_json.h',
    'include/report_plain.h',
    'include/rx_rule.h',
    'include/seltree.h',
    'include/seltree_struct.h',
    'include/symboltable.h',
    'include/tree.h',
    'include/url.h',
    'include/util.h',
    'src/aide.c',
    'src/attributes.c',
    'src/base64.c',
    'src/be.c',
    'src/commandconf.c',
    'src/conf_ast.c',
    'src/conf_eval.c',
    'src/db.c',
    'src/db_disk.c',
    'src/db_file.c',
    'src/db_list.c',
    'src/do_md.c',
    'src/file.c',
    'src/gen_list.c',
    'src/getopt.c',
    'src/getopt1.c',
    'src/hashsum.c',
    'src/list.c',
    'src/log.c',
    'src/md.c',
    'src/progress.c',
    'src/queue.c',
    'src/report.c',
    'src/report_json.c',
    'src/report_plain.c',
    'src/rx_rule.c',
    'src/seltree.c',
    'src/symboltable.c',
    'src/tree.c',
    'src/url.c',
    'src/util.c',
    conf_h,
    conf_yacc,
    conf_lex,
]

# Conditional source files
if e2fsattrs_dep.found()
    aide_sources += ['include/e2fsattrs.h', 'src/e2fsattrs.c']
endif

if curl_dep.found()
    aide_sources += ['include/fopen.h', 'src/fopen.c']
endif

# Define compiler flags
inc_dir = include_directories('include')

# Define aide executable

executable(
    'aide',
    aide_sources,
    dependencies: aide_deps,
    include_directories: inc_dir,
    install: true,
)

# Optional test executable
if check_dep.found()
    check_aide_sources = [
        'tests/check_aide.c',
        'tests/check_aide.h',
        'tests/check_attributes.c',
        'src/attributes.c',
        'tests/check_base64.c',
        'src/base64.c',
        'tests/check_hashsum.c',
        'src/hashsum.c',
        'tests/check_seltree.c',
        'src/seltree.c',
        'tests/check_progress.c',
        'src/md.c',
        'src/file.c',
        'src/log.c',
        'src/util.c',
        'src/list.c',
        'src/tree.c',
        'src/rx_rule.c',
    ]

    check_aide_deps = [m_dep, check_dep, gcrypt_dep, nettle_dep, pcre2_dep]

    check_aide = executable(
        'check_aide',
        check_aide_sources,
        include_directories: inc_dir,
        dependencies: check_aide_deps,
    )

    test('check_aide', check_aide)
endif

# Install man pages
install_man('doc/aide.1', 'doc/aide.conf.5')
