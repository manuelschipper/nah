source "${LIB_ROOT}/lib/util.sh"; util-setup
if [[ -f "${LIB_ROOT}/lib/cmd/${CMD}.sh" ]]; then
  source "${LIB_ROOT}/lib/cmd/${CMD}.sh"
  "homebrew-${CMD}" "$@"
fi
homebrew-update
