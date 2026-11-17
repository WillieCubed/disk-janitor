# bash completion for the normal job API
# shellcheck shell=bash disable=SC2207
_disk_janitor() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W 'submit status logs wait cancel help version' -- "$cur") )
  elif [ "${COMP_WORDS[1]}" = submit ]; then
    COMPREPLY=( $(compgen -c -- "$cur") )
  elif [ "${COMP_WORDS[1]}" = status ] && [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W --json -- "$cur") )
  elif [ "${COMP_WORDS[1]}" = logs ] && [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W '-f --follow' -- "$cur") )
  else
    local p ids=''
    for p in "${DISK_JANITOR_HOME:-$HOME/.disk-janitor}"/jobs/j-*; do
      [ ! -d "$p" ] || ids="$ids ${p##*/}"
    done
    COMPREPLY=( $(compgen -W "$ids" -- "$cur") )
  fi
}
complete -F _disk_janitor disk-janitor
