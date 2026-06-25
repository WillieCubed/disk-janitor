# bash completion for disk-janitor
# shellcheck shell=bash disable=SC2207
_disk_janitor() {
  local cur cmds
  cur="${COMP_WORDS[COMP_CWORD]}"
  cmds="install uninstall run status logs config version help"

  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    return
  fi

  case "${COMP_WORDS[1]}" in
    install)   COMPREPLY=( $(compgen -W "--with-agent-guidance --dry-run" -- "$cur") ) ;;
    uninstall) COMPREPLY=( $(compgen -W "--purge" -- "$cur") ) ;;
    run)       COMPREPLY=( $(compgen -W "--dry-run -n" -- "$cur") ) ;;
    logs)      COMPREPLY=( $(compgen -W "-f" -- "$cur") ) ;;
    *)         COMPREPLY=() ;;
  esac
}
complete -F _disk_janitor disk-janitor
