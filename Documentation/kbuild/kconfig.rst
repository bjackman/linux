=================================
Configuration targets and editors
=================================

This file contains some assistance for using ``make *config``.

Use ``make help`` to list all of the possible configuration targets.

The xconfig ('qconf'), menuconfig ('mconf'), and nconfig ('nconf')
programs also have embedded help text.  Be sure to check that for
navigation, search, and other general help text.

The gconfig ('gconf') program has limited help text.


General
=======

New kernel releases often introduce new config symbols.  Often more
important, new kernel releases may rename config symbols.  When
this happens, using a previously working .config file and running
"make oldconfig" won't necessarily produce a working new kernel
for you, so you may find that you need to see what NEW kernel
symbols have been introduced.

To see a list of new config symbols, use::

    cp user/some/old.config .config
    make listnewconfig

and the config program will list any new symbols, one per line.

Alternatively, you can use the brute force method::

    make oldconfig
    scripts/diffconfig .config.old .config | less


Environment variables
=====================

Environment variables for ``*config``:

``KCONFIG_CONFIG``
    This environment variable can be used to specify a default kernel config
    file name to override the default name of ".config".

``KCONFIG_DEFCONFIG_LIST``
    This environment variable specifies a list of config files which can be
    used as a base configuration in case the .config does not exist yet.
    Entries in the list are separated with whitespaces to each other, and
    the first one that exists is used.

``KCONFIG_OVERWRITECONFIG``
    If you set KCONFIG_OVERWRITECONFIG in the environment, Kconfig will not
    break symlinks when .config is a symlink to somewhere else.

``KCONFIG_WARN_UNKNOWN_SYMBOLS``
    This environment variable makes Kconfig warn about all unrecognized
    symbols in the config input.

``KCONFIG_WERROR``
    If set, Kconfig treats warnings as errors.

``CONFIG_``
    If you set ``CONFIG_`` in the environment, Kconfig will prefix all symbols
    with its value when saving the configuration, instead of using the
    default, ``CONFIG_``.

Environment variables for ``{allyes/allmod/allno/rand}config``:

``KCONFIG_ALLCONFIG``
    The allyesconfig/allmodconfig/allnoconfig/randconfig variants can also
    use the environment variable KCONFIG_ALLCONFIG as a flag or a filename
    that contains config symbols that the user requires to be set to a
    specific value.  If KCONFIG_ALLCONFIG is used without a filename where
    KCONFIG_ALLCONFIG == "" or KCONFIG_ALLCONFIG == "1", ``make *config``
    checks for a file named "all{yes/mod/no/def/random}.config"
    (corresponding to the ``*config`` command that was used) for symbol values
    that are to be forced.  If this file is not found, it checks for a
    file named "all.config" to contain forced values.

    This enables you to create "miniature" config (miniconfig) or custom
    config files containing just the config symbols that you are interested
    in.  Then the kernel config system generates the full .config file,
    including symbols of your miniconfig file.

    This ``KCONFIG_ALLCONFIG`` file is a config file which contains
    (usually a subset of all) preset config symbols.  These variable
    settings are still subject to normal dependency checks.

    Examples::

        KCONFIG_ALLCONFIG=custom-notebook.config make allnoconfig

    or::

        KCONFIG_ALLCONFIG=mini.config make allnoconfig

    or::

        make KCONFIG_ALLCONFIG=mini.config allnoconfig

    These examples will disable most options (allnoconfig) but enable or
    disable the options that are explicitly listed in the specified
    mini-config files.

Environment variables for ``randconfig``:

``KCONFIG_SEED``
    You can set this to the integer value used to seed the RNG, if you want
    to somehow debug the behaviour of the kconfig parser/frontends.
    If not set, the current time will be used.

``KCONFIG_PROBABILITY``
    This variable can be used to skew the probabilities. This variable can
    be unset or empty, or set to three different formats:

    =======================     ==================  =====================
    KCONFIG_PROBABILITY         y:n split           y:m:n split
    =======================     ==================  =====================
    unset or empty              50  : 50            33  : 33  : 34
    N                            N  : 100-N         N/2 : N/2 : 100-N
    [1] N:M                     N+M : 100-(N+M)      N  :  M  : 100-(N+M)
    [2] N:M:L                    N  : 100-N          M  :  L  : 100-(M+L)
    =======================     ==================  =====================

where N, M and L are integers (in base 10) in the range [0,100], and so
that:

    [1] N+M is in the range [0,100]

    [2] M+L is in the range [0,100]

Examples::

    KCONFIG_PROBABILITY=10
        10% of booleans will be set to 'y', 90% to 'n'
        5% of tristates will be set to 'y', 5% to 'm', 90% to 'n'
    KCONFIG_PROBABILITY=15:25
        40% of booleans will be set to 'y', 60% to 'n'
        15% of tristates will be set to 'y', 25% to 'm', 60% to 'n'
    KCONFIG_PROBABILITY=10:15:15
        10% of booleans will be set to 'y', 90% to 'n'
        15% of tristates will be set to 'y', 15% to 'm', 70% to 'n'

Environment variables for ``syncconfig``:

``KCONFIG_NOSILENTUPDATE``
    If this variable has a non-blank value, it prevents silent kernel
    config updates (requires explicit updates).

``KCONFIG_AUTOCONFIG``
    This environment variable can be set to specify the path & name of the
    "auto.conf" file.  Its default value is "include/config/auto.conf".

``KCONFIG_AUTOHEADER``
    This environment variable can be set to specify the path & name of the
    "autoconf.h" (header) file.
    Its default value is "include/generated/autoconf.h".


menuconfig
==========

Searching in menuconfig:

    The Search function searches for kernel configuration symbol
    names, so you have to know something close to what you are
    looking for.

    Example::

        /hotplug
        This lists all config symbols that contain "hotplug",
        e.g., HOTPLUG_CPU, MEMORY_HOTPLUG.

    For search help, enter / followed by TAB-TAB (to highlight
    <Help>) and Enter.  This will tell you that you can also use
    regular expressions (regexes) in the search string, so if you
    are not interested in MEMORY_HOTPLUG, you could try::

        /^hotplug

    When searching, symbols are sorted thus:

    - first, exact matches, sorted alphabetically (an exact match
      is when the search matches the complete symbol name);
    - then, other matches, sorted alphabetically.

    For example, ^ATH.K matches:

        ATH5K ATH9K ATH5K_AHB ATH5K_DEBUG [...] ATH6KL ATH6KL_DEBUG
        [...] ATH9K_AHB ATH9K_BTCOEX_SUPPORT ATH9K_COMMON [...]

    of which only ATH5K and ATH9K match exactly and so are sorted
    first (and in alphabetical order), then come all other symbols,
    sorted in alphabetical order.

    In this menu, pressing the key in the (#) prefix will jump
    directly to that location. You will be returned to the current
    search results after exiting this new menu.

User interface options for 'menuconfig':

``MENUCONFIG_COLOR``
    It is possible to select different color themes using the variable
    MENUCONFIG_COLOR.  To select a theme use::

        make MENUCONFIG_COLOR=<theme> menuconfig

    Available themes are::

      - mono       => selects colors suitable for monochrome displays
      - blackbg    => selects a color scheme with black background
      - classic    => theme with blue background. The classic look
      - bluetitle  => a LCD friendly version of classic. (default)

``MENUCONFIG_MODE``
    This mode shows all sub-menus in one large tree.

    Example::

        make MENUCONFIG_MODE=single_menu menuconfig


nconfig
=======

nconfig is an alternate text-based configurator.  It lists function
keys across the bottom of the terminal (window) that execute commands.
You can also just use the corresponding numeric key to execute the
commands unless you are in a data entry window.  E.g., instead of F6
for Save, you can just press 6.

Use F1 for Global help or F3 for the Short help menu.

Searching in nconfig:

    You can search either in the menu entry "prompt" strings
    or in the configuration symbols.

    Use / to begin a search through the menu entries.  This does
    not support regular expressions.  Use <Down> or <Up> for
    Next hit and Previous hit, respectively.  Use <Esc> to
    terminate the search mode.

    F8 (SymSearch) searches the configuration symbols for the
    given string or regular expression (regex).

    In the SymSearch, pressing the key in the (#) prefix will
    jump directly to that location. You will be returned to the
    current search results after exiting this new menu.

Environment variables:

``NCONFIG_MODE``
    This mode shows all sub-menus in one large tree.

    Example::

        make NCONFIG_MODE=single_menu nconfig


xconfig
=======

Searching in xconfig:

    The Search function searches for kernel configuration symbol
    names, so you have to know something close to what you are
    looking for.

    Example::

        Ctrl-F hotplug

    or::

        Menu: File, Search, hotplug

    lists all config symbol entries that contain "hotplug" in
    the symbol name.  In this Search dialog, you may change the
    config setting for any of the entries that are not grayed out.
    You can also enter a different search string without having
    to return to the main menu.

Conflict resolution
-------------------

    xconfig has support for conflict resolution. A conflict is in this case any
    situation where you want to change the value of a symbol, but
    unfulfilled dependencies prevent this. You can create a list of symbols
    and their desired values, and the conflict resolver will calculate a series
    of changes in xconfig, which allows setting the symbols to their desired
    values.

Requirements:

    To use the conflict resolver, PicoSAT needs to be installed as a library.

    Debian-based distributions::

        sudo apt install picosat

    Fedora::

        sudo dnf install picosat

    You can also build PicoSAT yourself from the `sources
    <https://fmv.jku.at/picosat/picosat-965.tar.gz>`_. The conflict resolver
    requires that PicoSAT is built with tracing enabled (e.g., using the
    configure.sh script with the "--trace" option). It expects the shared
    library to be named "libpicosat-trace.so", "libpicosat-trace.so.0" or
    "libpicosat-trace.so.1".

Usage:

    To add a symbol to the list of symbols whose values should be changed (that
    is, the 'conflict'), you select the symbol in the main view of xconfig. With
    the button "Add symbol" you add the symbol to the conflict, which makes it
    appear in a table below the main view. You need to switch to "Show Prompt
    Options" under the tab "Option" if the symbol is hidden in the main view.
    You can set the desired value of a symbol by either clicking on the
    corresponding cell in the column "Wanted Value," or by selecting the
    symbol's row and using one of the buttons above the table.

    Once the 'conflict' is declared, the solutions can be calculated using the
    button "Calculate Fixes". Once calculated, they appear in the menu on the
    bottom right. You can select a solution from up to three candidates. The
    solutions are presented in a table that shows which values the symbols need
    to have to resolve the conflict. Using the button "Apply selected solution"
    the indicated changes can automatically be applied. If you want to change
    the values manually, the symbols are color-coded to indicate the order in
    which they need to be set: Green means that a symbol is already set to the
    calculated value. Gray means that a symbol cannot yet be set to the
    calculated value and that other symbols' values need to be changed first.
    Red means that a symbol is not yet set to the calculated value, but that you
    can set it to the calculated value.

    Note that in rare cases the conflict resolver cannot resolve the conflict
    even when a solution exists, it suggests unnecessary changes, or it suggests
    changes that do not resolve the conflict.

gconfig
=======

Searching in gconfig:

    There is no search command in gconfig.  However, gconfig does
    have several different viewing choices, modes, and options.
