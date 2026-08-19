project(
    'nftconf',
    version: run_command(
        'sh',
        '-c', 'v=$(git describe --tags --always --dirty 2>/dev/null || true); v=${v#v}; [ -n "$v" ] && printf "%s" "$v" || printf "1.2.0"',
        check: false,
    ).stdout().strip(),
    license: 'AGPL-3.0-or-later',
)

project_author = 'Lenik'
project_email = 'nftconf@bodz.net'
project_year = 2026

py = import('python').find_installation('python3')
fs = import('fs')
asciidoctor = find_program('asciidoctor', required: true)
pandoc = find_program('pandoc', required: true)
makeinfo = find_program('makeinfo', required: true)

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
localedir = prefix / get_option('localedir')
mandir = prefix / get_option('mandir')
infodir = prefix / get_option('infodir')
pkgdocdir = datadir / 'doc' / meson.project_name()

subdir('po')

# Substitute meson.project_version() (git describe) into nftconf_app.
nftconf_app_cdata = configuration_data()
nftconf_app_cdata.set('VERSION', meson.project_version())
nftconf_init_py = configure_file(
    input: 'nftconf_app' / '__init__.py.in',
    output: 'nftconf_app_init.py',
    configuration: nftconf_app_cdata,
)
install_data(
    nftconf_init_py,
    install_dir: py.get_install_dir() / 'nftconf_app',
    rename: '__init__.py',
)
# Uninstalled imports (PYTHONPATH=source, tests, builddir launcher) read
# nftconf_app/ from the source tree; copy the substituted file there.
run_command(
    py,
    '-c',
    'import shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2])',
    meson.current_build_dir() / 'nftconf_app_init.py',
    meson.project_source_root() / 'nftconf_app' / '__init__.py',
    check: true,
)

nftconf_exe = custom_target(
    'nftconf',
    input: 'nftconf.py',
    output: 'nftconf',
    command: [
        py,
        '-c',
        '''
import os, shutil, sys
src, dst, root = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.copyfile(src, dst)
os.chmod(dst, 0o755)
marker = os.path.join(os.path.dirname(os.path.abspath(dst)), ".nftconf-source-root")
open(marker, "w", encoding="utf-8").write(root.strip() + chr(10))
''',
        '@INPUT@',
        '@OUTPUT@',
        meson.project_source_root(),
    ],
    build_by_default: true,
    install: true,
    install_dir: bindir,
)

# Pure-Python package next to site-packages
install_subdir(
    'nftconf_app',
    install_dir: py.get_install_dir(),
    exclude_directories: ['__pycache__'],
    exclude_files: ['*.pyc', '__init__.py', '__init__.py.in'],
)

install_data(
    'nftconf.bash',
    install_dir: datadir / 'bash-completion' / 'completions',
    rename: 'nftconf',
)

install_data(
    [
        'LICENSE',
        'README.md',
        'README-zh.md',
        'guide.md',
    ],
    install_dir: pkgdocdir,
)

# --- man page (AsciiDoctor) -------------------------------------------------
manpage = custom_target(
    'nftconf.1',
    input: 'docs/nftconf.1.adoc',
    output: 'nftconf.1',
    command: [
        asciidoctor,
        '-b', 'manpage',
        '-a', 'project-version=' + meson.project_version(),
        '-a', 'project-year=' + project_year.to_string(),
        '-a', 'project-author=' + project_author,
        '-a', 'project-email=' + project_email,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: mandir / 'man1',
)

manpage_langs = ['de', 'eo', 'fr', 'it', 'ja', 'ko', 'th', 'vi', 'zh_CN', 'zh_TW']
foreach lang : manpage_langs
    custom_target(
        'nftconf-man-' + lang,
        input: 'docs' / lang / 'nftconf.1.adoc',
        output: 'nftconf.1.' + lang,
        command: [
            asciidoctor,
            '-b', 'manpage',
            '-a', 'project-version=' + meson.project_version(),
            '-a', 'project-year=' + project_year.to_string(),
            '-a', 'project-author=' + project_author,
            '-a', 'project-email=' + project_email,
            '-o', '@OUTPUT@',
            '@INPUT@',
        ],
        build_by_default: true,
    )
endforeach

meson.add_install_script(
    'sh',
    '-euc',
    '''
        build="@0@"
        mandir="@1@"
        for lang in de eo fr it ja ko th vi zh_CN zh_TW; do
            dest="${DESTDIR}${mandir}/${lang}/man1"
            mkdir -p "$dest"
            install -m644 "$build/nftconf.1.$lang" "$dest/nftconf.1"
        done
    '''.format(meson.project_build_root(), mandir),
)

# --- info manual: AsciiDoctor → DocBook → Texinfo → info --------------------
nftconf_docbook = custom_target(
    'nftconf-docbook',
    input: 'docs/nftconf.adoc',
    output: 'nftconf.xml',
    command: [
        asciidoctor,
        '-b', 'docbook5',
        '-a', 'project-version=' + meson.project_version(),
        '-a', 'project-year=' + project_year.to_string(),
        '-a', 'project-author=' + project_author,
        '-a', 'project-email=' + project_email,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)

nftconf_texi = custom_target(
    'nftconf-texi',
    input: nftconf_docbook,
    output: 'nftconf.texi',
    command: [
        'sh', '-euc',
        '''
            pandoc -f docbook -t texinfo -o "$2" "$1"
            # Ensure Info directory entry and Top node wiring.
            if ! grep -q '@direntry' "$2"; then
                tmp=$(mktemp)
                {
                    echo '@setfilename nftconf.info'
                    echo '@settitle nftconf'
                    echo '@dircategory System Administration'
                    echo '@direntry'
                    echo '* nftconf: (nftconf).       Declarative nftables configuration.'
                    echo '@end direntry'
                    echo
                    cat "$2"
                } >"$tmp"
                mv "$tmp" "$2"
            fi
        ''',
        'sh', '@INPUT@', '@OUTPUT@',
    ],
    build_by_default: true,
)

nftconf_info = custom_target(
    'nftconf.info',
    input: nftconf_texi,
    output: 'nftconf.info',
    command: [
        makeinfo,
        '--no-split',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
    install: true,
    install_dir: infodir,
)

test(
    'python-unit',
    py,
    args: [
        '-m', 'unittest', 'discover',
        '-s', (meson.project_source_root() / 'tests'),
        '-p', 'test_*.py',
    ],
    env: [
        'PYTHONPATH=' + meson.project_source_root(),
        'ZEPHYR_LOCALEDIR=' + (meson.project_build_root() / 'po'),
    ],
)

docker = find_program('docker', required: false)
if docker.found()
    test(
        'docker-function-cover',
        find_program(meson.project_source_root() / 'demo' / 'scripts' / 'function-cover.sh'),
        timeout: 600,
        is_parallel: false,
        suite: 'docker',
        env: ['NFTCONF_DEMO_DOWN=1'],
    )
endif

run_target(
    'posync',
    command: [
        'bash',
        '-euc', '''
            cd "@SOURCE_ROOT@/po"
            xgettext --from-code=UTF-8 --keyword=_ --language=Python --directory=.. --output=nftconf.pot --files-from=POTFILES
            while IFS= read -r lang; do
                [ -n "$lang" ] || continue
                case "$lang" in
                    '#'* ) continue ;;
                esac
                po_file="$lang.po"
                if [ ! -f "$po_file" ]; then
                    msginit --no-translator --input=nftconf.pot --locale="$lang" --output-file="$po_file"
                fi
                msgmerge --update --backup=none "$po_file" nftconf.pot
                msgattrib --no-obsolete --output-file="$po_file" "$po_file"
            done < LINGUAS
        ''',
    ],
)

run_target(
    'look',
    command: [
        'bash',
        '-euc', '''
            tmpdir=$(mktemp -d)
            DESTDIR=$tmpdir meson install -C "@BUILD_ROOT@"
            tree "$tmpdir"
            rm -fr "$tmpdir"
        ''',
    ],
)

run_target(
    'install-symlinks',
    command: [
        'bash',
        '-euc', '''
            prefix="@0@"
            bindir="@1@"
            datadir="@2@"
            mandir="@3@"
            infodir="@4@"
            mkdir -p "$bindir" "$datadir/bash-completion/completions" "$mandir/man1" "$infodir"
            sudo ln -sfn "@BUILD_ROOT@/nftconf" "$bindir/nftconf"
            sudo ln -sfn "@BUILD_ROOT@/nftconf.1" "$mandir/man1/nftconf.1"
            sudo ln -sfn "@BUILD_ROOT@/nftconf.info" "$infodir/nftconf.info"
            sudo ln -sfn "@SOURCE_ROOT@/nftconf.bash" "$datadir/bash-completion/completions/nftconf"
            printf "Symlinks installed under %s\n" "$prefix"
            printf "Set PYTHONPATH=%s when running the builddir binary.\n" "@SOURCE_ROOT@"
        '''.format(get_option('prefix'), bindir, datadir, mandir, infodir),
    ],
)

run_target(
    'uninstall-symlinks',
    command: [
        'bash',
        '-euc', '''
            prefix="@0@"
            bindir="@1@"
            datadir="@2@"
            mandir="@3@"
            infodir="@4@"
            for p in "$bindir/nftconf" "$mandir/man1/nftconf.1" "$infodir/nftconf.info" \
                     "$datadir/bash-completion/completions/nftconf"
            do
                if [ -L "$p" ]; then
                    sudo rm -f "$p"
                    printf "Removed %s\n" "$p"
                else
                    printf "Skipped (not a symlink): %s\n" "$p"
                fi
            done
        '''.format(get_option('prefix'), bindir, datadir, mandir, infodir),
    ],
)
