#compdef disk-janitor
_disk-janitor() {
  local -a commands jobs
  commands=('submit:submit a new command' 'status:inspect jobs and capacity' 'logs:read job output' 'wait:wait for a terminal outcome' 'cancel:cancel your job' 'help:show help' 'version:show version')
  if (( CURRENT == 2 )); then _describe -t commands 'command' commands; return; fi
  if [[ ${words[2]} == submit ]]; then _command_names; return; fi
  jobs=( ${DISK_JANITOR_HOME:-$HOME/.disk-janitor}/jobs/j-*(N:t) )
  _describe -t jobs 'job' jobs
  case ${words[2]} in
    status) _arguments '--json[machine-readable status]' ;;
    logs) _arguments '-f[follow output]' '--follow[follow output]' ;;
  esac
}
_disk-janitor "$@"
