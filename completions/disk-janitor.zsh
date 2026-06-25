#compdef disk-janitor
# zsh completion for disk-janitor

_disk-janitor() {
  local -a commands
  commands=(
    'install:configure dedup + schedule the weekly cleanup'
    'uninstall:reverse everything cleanly'
    'run:run the cleanup now'
    'status:show configuration and free space'
    'logs:show or follow the run log'
    'config:print the config file path and contents'
    'version:print version'
    'help:show help'
  )

  if (( CURRENT == 2 )); then
    _describe -t commands 'disk-janitor command' commands
    return
  fi

  case "${words[2]}" in
    install)   _arguments '--with-agent-guidance[manage worktree guidance in agent config files]' '--dry-run[preview only]' ;;
    uninstall) _arguments '--purge[also remove cargo-sweep and app state]' ;;
    run)       _arguments '(--dry-run -n)'{--dry-run,-n}'[report candidates, delete nothing]' ;;
    logs)      _arguments '-f[follow the log]' ;;
  esac
}

_disk-janitor "$@"
