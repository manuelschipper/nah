#!/bin/sh

# This script downloads the 'ghcup' binary into '~/.ghcup/bin/' and then runs an interactive
# installation that lets you choose various options. Below is a list of environment variables
# that affect the installation procedure.

# Main settings:
#   * BOOTSTRAP_HASKELL_NONINTERACTIVE - any non-empty value for noninteractive installation
#   * BOOTSTRAP_HASKELL_NO_UPGRADE - any nonzero value to not trigger the upgrade
#   * BOOTSTRAP_HASKELL_MINIMAL - any nonzero value to only install ghcup
#   * GHCUP_USE_XDG_DIRS - any nonzero value to respect The XDG Base Directory Specification
#   * BOOTSTRAP_HASKELL_VERBOSE - any nonzero value for more verbose installation
#   * BOOTSTRAP_HASKELL_GHC_VERSION - the ghc version to install
#   * BOOTSTRAP_HASKELL_CABAL_VERSION - the cabal version to install
#   * BOOTSTRAP_HASKELL_CABAL_XDG - don't disable the XDG logic (this doesn't force XDG though, because cabal is confusing)
#   * BOOTSTRAP_HASKELL_INSTALL_NO_STACK - disable installation of stack
#   * BOOTSTRAP_HASKELL_INSTALL_NO_STACK_HOOK - disable installation stack ghcup hook
#   * BOOTSTRAP_HASKELL_STACK_VERSION - the stack version to install
#   * BOOTSTRAP_HASKELL_INSTALL_HLS - whether to install hls
#   * BOOTSTRAP_HASKELL_HLS_VERSION - the hls version to install
#   * BOOTSTRAP_HASKELL_ADJUST_BASHRC - whether to adjust PATH in bashrc (prepend)
#   * BOOTSTRAP_HASKELL_ADJUST_CABAL_CONFIG - whether to adjust mingw paths in cabal.config on windows
#   * BOOTSTRAP_HASKELL_DOWNLOADER - which downloader to use (default: curl)
#   * GHCUP_BASE_URL - the base url for ghcup binary download (use this to overwrite https://downloads.haskell.org/~ghcup with a mirror)
#   * GHCUP_MSYS2_ENV - the msys2 environment to use on windows, see https://www.msys2.org/docs/environments/ (defaults to MINGW64, MINGW32 or CLANGARM64, depending on the architecture)

# License: LGPL-3.0


# safety subshell to avoid executing anything in case this script is not downloaded properly
(

die() {
    if [ -n "${NO_COLOR}" ] ; then
        (>&2 printf "%s\\n" "$1")
    else
        (>&2 printf "\\033[0;31m%s\\033[0m\\n" "$1")
    fi
    exit 2
}

plat="$(uname -s)"
arch=$(uname -m)
ghver="0.2.6.2"
: "${GHCUP_BASE_URL:=https://downloads.haskell.org/~ghcup}"

export GHCUP_SKIP_UPDATE_CHECK=yes
: "${BOOTSTRAP_HASKELL_DOWNLOADER:=curl}"

set_msys2_env_dir() {
    case "${GHCUP_MSYS2_ENV}" in
        "")
            case "${arch}" in
                x86_64|amd64)
                    GHCUP_MSYS2_ENV_DIR="mingw64" ;;
                i*86)
                    GHCUP_MSYS2_ENV_DIR="mingw32" ;;
                aarch64|arm64)
                    GHCUP_MSYS2_ENV_DIR="clangarm64" ;;
                *) die "Unknown architecture: ${arch}" ;;
            esac
            ;;
        MSYS)
            GHCUP_MSYS2_ENV_DIR="usr" ;;
        UCRT64)
            GHCUP_MSYS2_ENV_DIR="ucrt64" ;;
        CLANG64)
            GHCUP_MSYS2_ENV_DIR="clang64" ;;
        CLANGARM64)
            GHCUP_MSYS2_ENV_DIR="clangarm64" ;;
        CLANG32)
            GHCUP_MSYS2_ENV_DIR="clang32" ;;
        MINGW64)
            GHCUP_MSYS2_ENV_DIR="mingw64" ;;
        MINGW32)
            GHCUP_MSYS2_ENV_DIR="mingw32" ;;
        *)
            die "Invalid value for GHCUP_MSYS2_ENV. Valid values are: MSYS, UCRT64, CLANG64, CLANGARM64, CLANG32, MINGW64, MINGW32" ;;
    esac
}

case "${plat}" in
        MSYS*|MINGW*|CYGWIN*)
			: "${GHCUP_INSTALL_BASE_PREFIX:=/c}"
			GHCUP_DIR=$(cygpath -u "${GHCUP_INSTALL_BASE_PREFIX}/ghcup")
			GHCUP_CONFDIR=${GHCUP_DIR}
			GHCUP_BIN=$(cygpath -u "${GHCUP_INSTALL_BASE_PREFIX}/ghcup/bin")
			: "${GHCUP_MSYS2:=${GHCUP_DIR}/msys64}"
			set_msys2_env_dir
			;;
		*)
			: "${GHCUP_INSTALL_BASE_PREFIX:=$HOME}"

			if [ -n "${GHCUP_USE_XDG_DIRS}" ] ; then
				GHCUP_DIR=${XDG_DATA_HOME:=$HOME/.local/share}/ghcup
				GHCUP_CONFDIR=${XDG_DATA_HOME:=$HOME/.config}/ghcup
				GHCUP_BIN=${XDG_BIN_HOME:=$HOME/.local/bin}
			else
				GHCUP_DIR=${GHCUP_INSTALL_BASE_PREFIX}/.ghcup
				GHCUP_CONFDIR=${GHCUP_DIR}
				GHCUP_BIN=${GHCUP_INSTALL_BASE_PREFIX}/.ghcup/bin
			fi
			;;
esac

: "${BOOTSTRAP_HASKELL_GHC_VERSION:=recommended}"
: "${BOOTSTRAP_HASKELL_CABAL_VERSION:=recommended}"
: "${BOOTSTRAP_HASKELL_STACK_VERSION:=recommended}"
: "${BOOTSTRAP_HASKELL_HLS_VERSION:=recommended}"

warn() {
    if [ -n "${NO_COLOR}" ] ; then
        printf "%s\\n" "$1"
    else
        case "${plat}" in
                MSYS*|MINGW*|CYGWIN*)
                    # shellcheck disable=SC3037
                    echo -e "\\033[0;35m$1\\033[0m"
                    ;;
                *)
                    printf "\\033[0;35m%s\\033[0m\\n" "$1"
                    ;;
        esac
    fi
}

yellow() {
    if [ -n "${NO_COLOR}" ] ; then
        printf "%s\\n" "$1"
    else
        case "${plat}" in
                MSYS*|MINGW*|CYGWIN*)
                    # shellcheck disable=SC3037
                    echo -e "\\033[0;33m$1\\033[0m"
                    ;;
                *)
                    printf "\\033[0;33m%s\\033[0m\\n" "$1"
                    ;;
        esac
    fi
}

green() {
    if [ -n "${NO_COLOR}" ] ; then
        printf "%s\\n" "$1"
    else
        case "${plat}" in
                MSYS*|MINGW*|CYGWIN*)
                    # shellcheck disable=SC3037
                    echo -e "\\033[0;32m$1\\033[0m"
                    ;;
                *)
                    printf "\\033[0;32m%s\\033[0m\\n" "$1"
                    ;;
        esac
    fi
}

edo() {
    "$@" || die "\"$*\" failed!"
}

eghcup_raw() {
	"${GHCUP_BIN}/ghcup" "$@" || die "\"ghcup $*\" failed!"
}

eghcup() {
	_eghcup "$@"
}

_eghcup() {
	if [ -n "${BOOTSTRAP_HASKELL_YAML}" ] ; then
		args="-s ${BOOTSTRAP_HASKELL_YAML} --metadata-fetching-mode=Strict"
    else
		args="--metadata-fetching-mode=Strict"
	fi
    if [ -z "${BOOTSTRAP_HASKELL_VERBOSE}" ] ; then
        # shellcheck disable=SC2086
        "${GHCUP_BIN}/ghcup" ${args} "$@" || die "\"ghcup ${args} $*\" failed!"
    else
        # shellcheck disable=SC2086
        "${GHCUP_BIN}/ghcup" ${args} --verbose "$@" || die "\"ghcup ${args} --verbose $*\" failed!"
    fi
}

_ecabal() {
    # shellcheck disable=SC2317
    if [ -n "${CABAL_BIN}" ] ; then
        "${CABAL_BIN}" "$@"
    else
        # shellcheck disable=SC2086
        "${GHCUP_BIN}/cabal" "$@"
    fi
}

ecabal() {
	_ecabal "$@" || die "\"cabal $*\" failed!"
}

_done() {
	echo
	echo "==============================================================================="
	case "${plat}" in
   			MSYS*|MINGW*|CYGWIN*)
				green
				green "All done!"
				green
				green "In a new powershell or cmd.exe session, now you can..."
				green
				green "Start a simple repl via:"
				green "  ghci"
				green
				green "Start a new haskell project in the current directory via:"
				green "  cabal init --interactive"
				green
				green "To install other GHC versions and tools, run:"
				green "  ghcup tui"
				green
				green "To install system libraries and update msys2/mingw64,"
				green "open the \"Mingw haskell shell\""
				green "and the \"Mingw package management docs\""
				green "desktop shortcuts."
				green
				green "If you are new to Haskell, check out https://www.haskell.org/ghcup/steps/"
				;;
			*)
				green
				green "All done!"
				green
				green "To start a simple repl, run:"
				green "  ghci"
				green
				green "To start a new haskell project in the current directory, run:"
				green "  cabal init --interactive"
				green
				green "To install other GHC versions and tools, run:"
				green "  ghcup tui"
				green
				green "If you are new to Haskell, check out https://www.haskell.org/ghcup/steps/"
				;;

	esac


	exit 0
}

# @FUNCTION: posix_realpath
# @USAGE: <file>
# @DESCRIPTION:
# Portably gets the realpath and prints it to stdout.
# This was initially inspired by
#   https://gist.github.com/tvlooy/cbfbdb111a4ebad8b93e
#   and
#   https://stackoverflow.com/a/246128
#
# If the file does not exist, just prints it appended to the current directory.
# @STDOUT: realpath of the given file
posix_realpath() {
    [ -z "$1" ] && die "Internal error: no argument given to posix_realpath"
    current_loop=0
    max_loops=50
    mysource=$1
    # readlink and '[ -h $path ]' behave different wrt '/sbin/' and '/sbin', so we strip it
    mysource=${mysource%/}
    [ -z "${mysource}" ] && mysource=$1

    while [ -h "${mysource}" ]; do
        current_loop=$((current_loop+1))
        mydir="$( cd -P "$( dirname "${mysource}" )" > /dev/null 2>&1 && pwd )"
        mysource="$(readlink "${mysource}")"
        [ "${mysource%"${mysource#?}"}"x != '/x' ] && mysource="${mydir%/}/${mysource}"

        if [ ${current_loop} -gt ${max_loops} ] ; then
            (>&2 echo "${1}: Too many levels of symbolic links")
			echo "$1"
            return
        fi
    done
    mydir="$( cd -P "$( dirname "${mysource}" )" > /dev/null 2>&1 && pwd )"

    # TODO: better distinguish between "does not exist" and "permission denied"
    if [ -z "${mydir}" ] ; then
        (>&2 echo "${1}: Permission denied")
		echo "$(pwd)/$1"
    else
        echo "${mydir%/}/$(basename "${mysource}")"
    fi

    unset current_loop max_loops mysource mydir
}

download_ghcup() {

    case "${plat}" in
        "linux"|"Linux")
			case "${arch}" in
				x86_64|amd64)
					# we could be in a 32bit docker container, in which
					# case uname doesn't give us what we want
					if [ "$(getconf LONG_BIT)" = "32" ] ; then
						_url=${GHCUP_BASE_URL}/${ghver}/i386-linux-ghcup-${ghver}
					elif [ "$(getconf LONG_BIT)" = "64" ] ; then
						_url=${GHCUP_BASE_URL}/${ghver}/x86_64-linux-ghcup-${ghver}
					else
						die "Unknown long bit size: $(getconf LONG_BIT)"
					fi
					;;
				i*86)
					_url=${GHCUP_BASE_URL}/${ghver}/i386-linux-ghcup-${ghver}
					;;
				armv7*|*armv8l*)
                    # later versions don't support armv7 anymore
					_url=${GHCUP_BASE_URL}/0.1.40.0/armv7-linux-ghcup-0.1.40.0
					;;
				aarch64|arm64)
					# we could be in a 32bit docker container, in which
					# case uname doesn't give us what we want
					if [ "$(getconf LONG_BIT)" = "32" ] ; then
                        # later versions don't support armv7 anymore
						_url=${GHCUP_BASE_URL}/0.1.40.0/armv7-linux-ghcup-0.1.40.0
					elif [ "$(getconf LONG_BIT)" = "64" ] ; then
						_url=${GHCUP_BASE_URL}/${ghver}/aarch64-linux-ghcup-${ghver}
					else
						die "Unknown long bit size: $(getconf LONG_BIT)"
					fi
					;;
				*) die "Unknown architecture: ${arch}"
					;;
			esac
			;;
        "FreeBSD"|"freebsd")
			case "${arch}" in
				x86_64|amd64)
					;;
				i*86)
					die "i386 currently not supported!"
					;;
				*) die "Unknown architecture: ${arch}"
					;;
			esac
			_url=${GHCUP_BASE_URL}/${ghver}/x86_64-portbld-freebsd-ghcup-${ghver}
            ;;
        "OpenBSD"|"openbsd")
			case "${arch}" in
				x86_64|amd64)
					;;
				i*86)
					die "i386 currently not supported!"
					;;
				*) die "Unknown architecture: ${arch}"
					;;
			esac
			_url=${GHCUP_BASE_URL}/${ghver}/x86_64-openbsd-ghcup-${ghver}
            ;;
        "Darwin"|"darwin")
			case "${arch}" in
				x86_64|amd64)
					_url=${GHCUP_BASE_URL}/${ghver}/x86_64-apple-darwin-ghcup-${ghver}
					;;
				aarch64|arm64|armv8l)
					_url=${GHCUP_BASE_URL}/${ghver}/aarch64-apple-darwin-ghcup-${ghver}
					;;
				i*86)
					die "i386 currently not supported!"
					;;
				*) die "Unknown architecture: ${arch}"
					;;
			esac
			;;
        MSYS*|MINGW*|CYGWIN*)
			case "${arch}" in
				x86_64|amd64)
					_url=${GHCUP_BASE_URL}/${ghver}/x86_64-mingw64-ghcup-${ghver}.exe
					;;
				*) die "Unknown architecture: ${arch}"
					;;
			esac
			;;
        *) die "Unknown platform: ${plat}"
			;;
    esac
    case "${plat}" in
        MSYS*|MINGW*|CYGWIN*)
            case "${BOOTSTRAP_HASKELL_DOWNLOADER}" in
                "curl")
	                # shellcheck disable=SC2086
                    edo curl -Lf ${GHCUP_CURL_OPTS} "${_url}" > "${GHCUP_BIN}"/ghcup.exe
                    ;;
                "wget")
	                # shellcheck disable=SC2086
                    edo wget -O /dev/stdout ${GHCUP_WGET_OPTS} "${_url}" > "${GHCUP_BIN}"/ghcup.exe
                    ;;
                *)
                    die "Unknown downloader: ${BOOTSTRAP_HASKELL_DOWNLOADER}"
                    ;;
            esac
			edo chmod +x "${GHCUP_BIN}"/ghcup.exe
			;;
		*)
            case "${BOOTSTRAP_HASKELL_DOWNLOADER}" in
                "curl")
	                # shellcheck disable=SC2086
                    edo curl -Lf ${GHCUP_CURL_OPTS} "${_url}" > "${GHCUP_BIN}"/ghcup
                    ;;
                "wget")
	                # shellcheck disable=SC2086
                    edo wget -O /dev/stdout ${GHCUP_WGET_OPTS} "${_url}" > "${GHCUP_BIN}"/ghcup
                    ;;
                *)
                    die "Unknown downloader: ${BOOTSTRAP_HASKELL_DOWNLOADER}"
                    ;;
            esac
			edo chmod +x "${GHCUP_BIN}"/ghcup
			;;
	esac

	edo mkdir -p "${GHCUP_DIR}"

	# we may overwrite this in adjust_bashrc
	cat <<-EOF > "${GHCUP_DIR}"/env || die "Failed to create env file"
		case ":\$PATH:" in
		    *:"${GHCUP_BIN}":*)
		        ;;
		    *)
		        export PATH="${GHCUP_BIN}:\$PATH"
		        ;;
		esac
		case ":\$PATH:" in
		    *:"\$HOME/.cabal/bin":*)
		        ;;
		    *)
		        export PATH="\$HOME/.cabal/bin:\$PATH"
		        ;;
		esac
		EOF

	# shellcheck disable=SC1090
    edo . "${GHCUP_DIR}"/env
    case "${BOOTSTRAP_HASKELL_DOWNLOADER}" in
        "curl")
            eghcup_raw config set downloader Curl
            ;;
        "wget")
            eghcup_raw config set downloader Wget
            ;;
        *)
            die "Unknown downloader: ${BOOTSTRAP_HASKELL_DOWNLOADER}"
            ;;
    esac
}

# Figures out the users login shell and sets
# GHCUP_PROFILE_FILE and MY_SHELL variables.
find_shell() {
	case $SHELL in
		*/zsh) # login shell is zsh
			if [ -n "$ZDOTDIR" ]; then
				GHCUP_PROFILE_FILE="$ZDOTDIR/.zshrc"
			else
				GHCUP_PROFILE_FILE="$HOME/.zshrc"
			fi
			MY_SHELL="zsh" ;;
		*/bash) # login shell is bash
			GHCUP_PROFILE_FILE="$HOME/.bashrc"
			MY_SHELL="bash" ;;
		*/sh) # login shell is sh, but might be a symlink to bash or zsh
			if [ -n "${BASH}" ] ; then
				GHCUP_PROFILE_FILE="$HOME/.bashrc"
				MY_SHELL="bash"
			elif [ -n "${ZSH_VERSION}" ] ; then
				GHCUP_PROFILE_FILE="$HOME/.zshrc"
				MY_SHELL="zsh"
			else
				return
			fi
			;;
		*/fish) # login shell is fish
			GHCUP_PROFILE_FILE="$HOME/.config/fish/config.fish"
			MY_SHELL="fish" ;;
		*) return ;;
	esac
}

ask_base_channel() {
    if [ -n "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
        return 0
    fi
    echo "-------------------------------------------------------------------------------"
    warn ""
    warn "GHCup provides different binary distribution \"channels\". These are collections of tools"
    warn "and may differ in purpose and philosophy. First, we select the base channel."
    warn ""
	while true; do

        if [ "$preexisting_config_file" -eq 1 ] ; then
            warn "[K] Keep current config  [G] GHCup maintained  [V] Vanilla (upstream maintained)  [?] Help (default is \"K\")."
        else
            warn "[G] GHCup maintained  [V] Vanilla (upstream maintained)  [?] Help (default is \"G\")."
        fi
        warn ""

		read -r basechannel_answer </dev/tty

        # Handle the [K]eep choice only if we actually offered it
        if [ "$preexisting_config_file" -eq 1 ] ; then
            case $basechannel_answer in
                [Kk]* | "")
                    return 0
                    ;;
            esac
        fi

        # Handle the other choices
		case $basechannel_answer in
			[Gg]* | "")
				return 1
				;;
			[Vv]*)
				return 2
				;;
			*)
				echo "Possible choices are:"
				echo
                if [ "$preexisting_config_file" -eq 1 ] ; then
                    echo "[K]eep    - Do nothing and leave your existing GHCup config as-is"
                fi
                echo "[G]HCup   - The default channel maintained by GHCup developers"
                echo "            (receives QA and support from GHCup and may provide"
                echo "            unofficial bindists for less supported platforms)"
				echo "[V]anilla - Only contains unchanged upstream binary distributions"
                echo "            (is updated with newer releases faster since it receives no GHCup QA)"
				echo
                if [ "$preexisting_config_file" -eq 1 ] ; then
                    echo "Selecting GHCup or Vanilla will overwrite the channel config in"
                    echo "your existing GHCup installation."
                    echo
                fi
                echo "Please make your choice and press ENTER."
				;;
		esac
	done

	unset basechannel_answer
}

ask_prerelease_channel() {
    if [ -n "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
        return 0
    fi
    echo "-------------------------------------------------------------------------------"

    warn ""
    warn "Do you also want to enable the pre-releases channel, getting access to"
    warn "alpha, betas and release candidates?"
    warn ""
    warn "[N] No  [Y] Yes  [?] Help (default is \"N\")."
    warn ""
	while true; do

		read -r prereleasechannel_answer </dev/tty

		case $prereleasechannel_answer in
			[Nn]* | "")
				return 0
				;;
			[Yy]*)
				return 1
				;;
			*)
				echo "Possible choices are:"
				echo
                echo "N - No, don't enable prereleases (default)"
				echo "Y - Yes, enable prereleases"
				echo
				echo "Please make your choice and press ENTER."
				;;
		esac
	done

	unset prereleasechannel_answer
}

ask_cross_channel() {
    if [ -n "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
        return 0
    fi
	while true; do
		echo "-------------------------------------------------------------------------------"

		warn ""
        warn "Do you also want to enable the cross channel, getting access to"
        warn "experimental GHCJS, WASM, etc.?"
        warn ""
        warn "[N] No  [Y] Yes  [?] Help (default is \"N\")."
        warn ""

		read -r crosschannel_answer </dev/tty

		case $crosschannel_answer in
			[Nn]* | "")
				return 0
				;;
			[Yy]*)
				return 1
				;;
			*)
				echo "Possible choices are:"
				echo
                echo "N - No, don't enable the cross channel (default)"
				echo "Y - Yes, enable the cross channel"
				echo
				echo "Please make your choice and press ENTER."
				;;
		esac
	done

	unset crosschannel_answer
}

ask_thirdparty_channel() {
    if [ -n "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
        return 0
    fi
	while true; do
		echo "-------------------------------------------------------------------------------"

		warn ""
        warn "Do you also want to enable the 3rdparty channel, getting access to"
        warn "to various non-core tools such as hlint, dhall and ormolu?"
        warn ""
        warn "[N] No  [Y] Yes  [?] Help (default is \"N\")."
        warn ""

		read -r thirdparty_answer </dev/tty

		case $thirdparty_answer in
			[Nn]* | "")
				return 0
				;;
			[Yy]*)
				return 1
				;;
			*)
				echo "Possible choices are:"
				echo
                echo "N - No, don't enable the cross channel (default)"
				echo "Y - Yes, enable the cross channel"
				echo
				echo "Please make your choice and press ENTER."
				;;
		esac
	done

	unset thirdparty_answer
}


# Ask user if they want to adjust the bashrc.
ask_bashrc() {
	if [ -n "${BOOTSTRAP_HASKELL_ADJUST_BASHRC}" ] ; then
		return 1
	elif [ -z "${MY_SHELL}" ] ; then
		return 0
	fi

	while true; do
		if [ -z "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
			echo "-------------------------------------------------------------------------------"

			warn ""
			warn "Detected ${MY_SHELL} shell on your system..."
			warn "Do you want ghcup to automatically add the required PATH variable to \"${GHCUP_PROFILE_FILE}\"?"
			warn ""
			warn "[P] Yes, prepend  [A] Yes, append  [N] No  [?] Help (default is \"P\")."
			warn ""

			read -r bashrc_answer </dev/tty
		else
			return 0
		fi
		case $bashrc_answer in
			[Pp]* | "")
				return 1
				;;
			[Aa]*)
				return 2
				;;
			[Nn]*)
				return 0
                ;;
			*)
				echo "Possible choices are:"
				echo
				echo "P - Yes, prepend to PATH, taking precedence (default)"
				echo "A - Yes, append to PATH"
				echo "N - No, don't mess with my configuration"
				echo
				echo "Please make your choice and press ENTER."
				;;
		esac
	done

	unset bashrc_answer
}

# Needs 'find_shell' to be called beforehand.
adjust_bashrc() {
	case $1 in
		1)
			cat <<-EOF > "${GHCUP_DIR}"/env || die "Failed to create env file"
				case ":\$PATH:" in
				    *:"${GHCUP_BIN}":*)
				        ;;
				    *)
				        export PATH="${GHCUP_BIN}:\$PATH"
				        ;;
				esac
				case ":\$PATH:" in
				    *:"\$HOME/.cabal/bin":*)
				        ;;
				    *)
				        export PATH="\$HOME/.cabal/bin:\$PATH"
				        ;;
				esac
				EOF
			;;
		2)
			cat <<-EOF > "${GHCUP_DIR}"/env || die "Failed to create env file"
				case ":\$PATH:" in
				    *:"\$HOME/.cabal/bin":*)
				        ;;
				    *)
				        export PATH="\$PATH:\$HOME/.cabal/bin"
				        ;;
				esac
				case ":\$PATH:" in
				    *:"${GHCUP_BIN}":*)
				        ;;
				    *)
				        export PATH="\$PATH:${GHCUP_BIN}"
				        ;;
				esac
				EOF
			;;
		*) ;;
	esac

	case $1 in
		1 | 2)
			case $MY_SHELL in
				"")
					warn_path "Couldn't figure out login shell!"
					return
					;;
				fish)
					mkdir -p "${GHCUP_PROFILE_FILE%/*}"
					sed -i -e '/# ghcup-env$/d' "$(posix_realpath "${GHCUP_PROFILE_FILE}")"
					case $1 in
						1)
							printf "\n%s" "set -q GHCUP_INSTALL_BASE_PREFIX[1]; or set GHCUP_INSTALL_BASE_PREFIX \$HOME ; set -gx PATH \$HOME/.cabal/bin $GHCUP_BIN \$PATH # ghcup-env" >> "${GHCUP_PROFILE_FILE}"
							;;
						2)
							printf "\n%s" "set -q GHCUP_INSTALL_BASE_PREFIX[1]; or set GHCUP_INSTALL_BASE_PREFIX \$HOME ; set -gx PATH \$HOME/.cabal/bin \$PATH $GHCUP_BIN # ghcup-env" >> "${GHCUP_PROFILE_FILE}"
							;;
					esac
					;;
				bash)
					sed -i -e '/# ghcup-env$/d' "$(posix_realpath "${GHCUP_PROFILE_FILE}")"
					printf "\n%s" "[ -f \"${GHCUP_DIR}/env\" ] && . \"${GHCUP_DIR}/env\" # ghcup-env" >> "${GHCUP_PROFILE_FILE}"
					case "${plat}" in
						"Darwin"|"darwin")
							if ! grep -q "ghcup-env" "${HOME}/.bash_profile" ; then
								printf "\n%s" "[[ -f ~/.bashrc ]] && . ~/.bashrc # ghcup-env" >> "${HOME}/.bash_profile"
							fi
							;;
   						MSYS*|MINGW*|CYGWIN*)
							if [ ! -e "${HOME}/.bash_profile" ] ; then
								echo '# generated by ghcup' > "${HOME}/.bash_profile"
								echo 'test -f ~/.profile && . ~/.profile' >> "${HOME}/.bash_profile"
								echo 'test -f ~/.bashrc && . ~/.bashrc' >> "${HOME}/.bash_profile"
							fi
							;;
					esac
					;;

				zsh)
					sed -i -e '/# ghcup-env$/d' "$(posix_realpath "${GHCUP_PROFILE_FILE}")"
					printf "\n%s" "[ -f \"${GHCUP_DIR}/env\" ] && . \"${GHCUP_DIR}/env\" # ghcup-env" >> "${GHCUP_PROFILE_FILE}"
					;;
			esac
            if [ -e "$HOME/.profile" ] ; then
					sed -i -e '/# ghcup-env$/d' "$(posix_realpath "$HOME/.profile")"
					printf "\n%s" "[ -f \"${GHCUP_DIR}/env\" ] && . \"${GHCUP_DIR}/env\" # ghcup-env" >> "$HOME/.profile"
            fi
			echo
			echo "==============================================================================="
			echo
			warn "OK! ${GHCUP_PROFILE_FILE} has been modified. Restart your terminal for the changes to take effect,"
			warn "or type \". ${GHCUP_DIR}/env\" to apply them in your current terminal session."
			return
			;;
		*)
			warn_path
			;;
	esac
}

warn_path() {
	echo
	echo "==============================================================================="
	echo
	[ -n "$1" ] && warn "$1"
	yellow "In order to run ghc and cabal, you need to adjust your PATH variable."
	yellow "To do so, you may want to run 'source $GHCUP_DIR/env' in your current terminal"
	yellow "session as well as your shell configuration (e.g. ~/.bashrc)."

}

adjust_cabal_config() {
    if [ -n "${CABAL_DIR}" ] ; then
        cabal_bin="${CABAL_DIR}/bin"
    else
        cabal_bin="$HOME/AppData/Roaming/cabal/bin"
    fi
    ecabal user-config -a "extra-prog-path: $(cygpath -w "$GHCUP_BIN"), $(cygpath -w "$cabal_bin"), $(cygpath -w "$GHCUP_MSYS2/${GHCUP_MSYS2_ENV_DIR}/bin"), $(cygpath -w "$GHCUP_MSYS2"/usr/bin)" -a "extra-include-dirs: $(cygpath -w "$GHCUP_MSYS2/${GHCUP_MSYS2_ENV_DIR}/include")" -a "extra-lib-dirs: $(cygpath -w "$GHCUP_MSYS2/${GHCUP_MSYS2_ENV_DIR}/lib")" -f init
}

ask_cabal_config_init() {
	case "${plat}" in
   			MSYS*|MINGW*|CYGWIN*)
				if [ -n "${BOOTSTRAP_HASKELL_ADJUST_CABAL_CONFIG}" ] ; then
					return 1
				fi

				if [ -z "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
					echo "-------------------------------------------------------------------------------"
					warn "Create an initial cabal.config including relevant msys2 paths (recommended)?"
					warn "[Y] Yes  [N] No  [?] Help (default is \"Y\")."
					echo
					while true; do
						read -r mingw_answer </dev/tty

						case $mingw_answer in
							[Yy]* | "")
								return 1 ;;
							[Nn]*)
								return 0 ;;
							*)
								echo "Possible choices are:"
								echo
								echo "Y - Yes, create a cabal.config with pre-set paths to msys2/mingw64 (default)"
								echo "N - No, leave the current/default cabal config untouched"
								echo
								echo "Please make your choice and press ENTER."
								;;
						esac
					done
				else
					return 0
				fi
				;;
	esac

	unset mingw_answer

    return 0
}

do_cabal_config_init() {
	case "${plat}" in
   			MSYS*|MINGW*|CYGWIN*)
		case $1 in
			1)
				adjust_cabal_config
				;;
			0)
				warn "Make sure that your global cabal.config references the correct mingw64 paths (extra-prog-path, extra-include-dirs and extra-lib-dirs)."
				warn "And set the environment variable GHCUP_MSYS2 to the root path of your msys2 installation."
				sleep 5
				return ;;
			*) ;;
		esac
	esac
}

ask_hls() {
	if [ -n "${BOOTSTRAP_HASKELL_INSTALL_HLS}" ] ; then
		return 1
	fi

	if [ -z "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
		echo "-------------------------------------------------------------------------------"

		warn "Do you want to install haskell-language-server (HLS)?"
		warn "HLS is a language-server that provides IDE-like functionality"
		warn "and can integrate with different editors, such as Vim, Emacs, VS Code, Atom, ..."
		warn "Also see https://haskell-language-server.readthedocs.io/en/stable/"
		warn ""
		warn "[Y] Yes  [N] No  [?] Help (default is \"N\")."
		warn ""

		while true; do
			read -r hls_answer </dev/tty

			case $hls_answer in
				[Yy]*)
					return 1
					;;
				[Nn]* | "")
					return 0
					;;
				*)
					echo "Possible choices are:"
					echo
					echo "Y - Yes, install the haskell-language-server"
					echo "N - No, don't install anything more (default)"
					echo
					echo "Please make your choice and press ENTER."
					;;
			esac
		done
	else
		return 0
	fi

	unset hls_answer
}

ask_stack() {
    if [ -n "${BOOTSTRAP_HASKELL_INSTALL_NO_STACK}" ] ; then
		return 0
    elif [ -n "${BOOTSTRAP_HASKELL_INSTALL_NO_STACK_HOOK}" ] ; then
		return 1
	fi

	if [ -z "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
		echo "-------------------------------------------------------------------------------"

		warn "Do you want to enable better integration of stack with GHCup?"
        warn "This means that stack won't install its own GHC versions, but uses GHCup's."
        warn "For more information see:"
        warn "  https://docs.haskellstack.org/en/stable/configure/customisation_scripts/#ghc-installation-customisation"
        warn "If you want to keep stacks vanilla behavior, answer 'No'."
		warn ""
		warn "[Y] Yes  [N] No  [?] Help (default is \"Y\")."
		warn ""

		while true; do
			read -r stack_answer </dev/tty

			case $stack_answer in
				[Yy]* | "")
					return 2 ;;
				[Nn]*)
					return 1 ;;
				*)
					echo "Possible choices are:"
					echo
                    echo "Y - Yes, enable better integration (default)"
					echo "N - No, keep stacks vanilla behavior"
					echo
					echo "Please make your choice and press ENTER."
					;;
			esac
		done
	else
		return 2
	fi

	unset stack_answer
}

find_stack_root() {
    if [ -n "${STACK_ROOT}" ] ; then
        echo "${STACK_ROOT}"
    elif [ -n "${STACK_XDG}" ] ; then
        echo "${XDG_DATA_HOME:-$HOME/.local/share}/stack"
    else
        echo "${HOME}/.stack"
    fi
}

find_shell


echo
echo "Welcome to Haskell!"
echo
echo "This script can download and install the following binaries:"
echo "  * ghcup - The Haskell toolchain installer"
echo "  * ghc   - The Glasgow Haskell Compiler"
echo "  * cabal - The Cabal build tool for managing Haskell software"
echo "  * stack - A cross-platform program for developing Haskell projects (similar to cabal)"
echo "  * hls   - (optional) A language server for developers to integrate with their editor/IDE"
echo
if [ -z "${GHCUP_USE_XDG_DIRS}" ] ; then
	echo "ghcup installs only into the following directory,"
    echo "which can be removed anytime:"
	case "${plat}" in
   			MSYS*|MINGW*|CYGWIN*)
				echo "  $(cygpath -w "$GHCUP_DIR")"
				;;
			*)
				echo "  $GHCUP_DIR"
				;;
	esac
else
	echo "ghcup installs into XDG directories as long as"
    echo "'GHCUP_USE_XDG_DIRS' is set."
fi
echo

if [ -z "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
    warn "Press ENTER to proceed or ctrl-c to abort."
    warn "Note that this script can be re-run at any given time."
    # Wait for user input to continue.
    # shellcheck disable=SC2034
    read -r answer </dev/tty
fi

preexisting_config_file=0
test -f "${GHCUP_CONFDIR}/config.yaml" && preexisting_config_file=1

edo mkdir -p "${GHCUP_BIN}"

if command -V "ghcup" >/dev/null 2>&1 ; then
    if [ -z "${BOOTSTRAP_HASKELL_NO_UPGRADE}" ] ; then
        download_ghcup
    fi
else
	download_ghcup
fi

echo
if [ -n "${BOOTSTRAP_HASKELL_YAML}" ] ; then (>&2 ghcup -s "${BOOTSTRAP_HASKELL_YAML}" tool-requirements) ; else (>&2 ghcup tool-requirements) ; fi
echo

if [ -z "${BOOTSTRAP_HASKELL_NONINTERACTIVE}" ] ; then
    echo
    warn "Press ENTER to proceed or ctrl-c to abort."
    echo

    # Wait for user input to continue.
    # shellcheck disable=SC2034
    read -r answer </dev/tty
fi

if [ -z "${BOOTSTRAP_HASKELL_MINIMAL}" ] ; then
    ask_base_channel
    ask_base_channel_answer=$?
    if [ $ask_base_channel_answer != 0 ] ; then
        ask_prerelease_channel
        ask_prerelease_channel_answer=$?
        ask_cross_channel
        ask_cross_channel_answer=$?
        ask_thirdparty_channel
        ask_thirdparty_channel_answer=$?
    fi
fi
ask_bashrc
ask_bashrc_answer=$?
ask_cabal_config_init
ask_cabal_config_init_answer=$?
if [ -z "${BOOTSTRAP_HASKELL_MINIMAL}" ] ; then
	  ask_hls
	  ask_hls_answer=$?
	  ask_stack
	  ask_stack_answer=$?
fi

case $ask_base_channel_answer in
	1)
        _eghcup config set url-source GHCupURL
        ;;
    2)
        _eghcup config set url-source vanilla
        ;;
    *) ;;
esac

case $ask_prerelease_channel_answer in
    1)
        _eghcup config add-release-channel prereleases
        ;;
    *) ;;
esac

case $ask_cross_channel_answer in
    1)
        _eghcup config add-release-channel cross
        ;;
    *) ;;
esac

case $ask_thirdparty_channel_answer in
    1)
        _eghcup config add-release-channel 3rdparty
        ;;
    *) ;;
esac

if [ -z "${BOOTSTRAP_HASKELL_MINIMAL}" ] ; then
	eghcup --cache install ghc "${BOOTSTRAP_HASKELL_GHC_VERSION}"

	eghcup set ghc "${BOOTSTRAP_HASKELL_GHC_VERSION}"
	eghcup --cache install cabal "${BOOTSTRAP_HASKELL_CABAL_VERSION}"

	do_cabal_config_init $ask_cabal_config_init_answer

    if [ -z "${BOOTSTRAP_HASKELL_CABAL_XDG}" ] ; then
        # disable XDG if we can
        if [ -e "${XDG_CONFIG_HOME:-"$HOME/.config"}/cabal" ] || [ -n "${CABAL_DIR}" ] || [ -n "${CABAL_CONFIG}" ] ; then
            :
        else
            edo mkdir -p "${HOME}/.cabal"
        fi
    fi

	edo cabal update --ignore-project
else # don't install ghc and cabal
	case "${plat}" in
   			MSYS*|MINGW*|CYGWIN*)
				# need to bootstrap cabal to initialize config on windows
				# we'll remove it afterwards
				tmp_dir="$(mktemp -d)"
				eghcup --cache install cabal -i "${tmp_dir}" "${BOOTSTRAP_HASKELL_CABAL_VERSION}"
				CABAL_BIN="${tmp_dir}/cabal" do_cabal_config_init $ask_cabal_config_init_answer
				rm "${tmp_dir}/cabal"
				unset tmp_dir
				;;
			*)
				;;
	esac
fi

case $ask_hls_answer in
	1)
            (_eghcup --cache install hls "${BOOTSTRAP_HASKELL_HLS_VERSION}") ||
		warn "HLS installation failed, continuing anyway"
		;;
	*) ;;
esac

case $ask_stack_answer in
	1)
            (_eghcup --cache install stack "${BOOTSTRAP_HASKELL_STACK_VERSION}") ||
		die "Stack installation failed"
		;;
	2)
            (_eghcup --cache install stack "${BOOTSTRAP_HASKELL_STACK_VERSION}") ||
		die "Stack installation failed"
        stack_root="$(find_stack_root)"
        edo mkdir -p "${stack_root}"/hooks
        hook_exe="${stack_root}"/hooks/ghc-install.sh
        hook_url="https://www.haskell.org/ghcup/sh/hooks/stack/ghc-install.sh"

        if [ -e "${hook_exe}" ] ; then
            warn "$hook_exe already exists, skipping hook installation."
            warn "If you want to reinstall the hook, delete it manually and re-run"
            warn "this script!"
        else
            case "${BOOTSTRAP_HASKELL_DOWNLOADER}" in
                "curl")
                    # shellcheck disable=SC2086
                    edo curl -Lf ${GHCUP_CURL_OPTS} "${hook_url}" > "${hook_exe}"
                    ;;
                "wget")
                    # shellcheck disable=SC2086
                    edo wget -O /dev/stdout ${GHCUP_WGET_OPTS} "${hook_url}" > "${hook_exe}"
                    ;;
                *)
                    die "Unknown downloader: ${BOOTSTRAP_HASKELL_DOWNLOADER}"
                    ;;
            esac
            edo chmod +x "${hook_exe}"
        fi

		;;
	*) ;;
esac


adjust_bashrc $ask_bashrc_answer


_done

)

# vim: tabstop=4 shiftwidth=4 expandtab
