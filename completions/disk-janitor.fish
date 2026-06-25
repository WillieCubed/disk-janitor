# fish completion for disk-janitor

# subcommands (only when no subcommand yet)
complete -c disk-janitor -f -n __fish_use_subcommand -a install   -d "configure dedup + schedule the weekly cleanup"
complete -c disk-janitor -f -n __fish_use_subcommand -a uninstall -d "reverse everything cleanly"
complete -c disk-janitor -f -n __fish_use_subcommand -a run       -d "run the cleanup now"
complete -c disk-janitor -f -n __fish_use_subcommand -a status    -d "show configuration and free space"
complete -c disk-janitor -f -n __fish_use_subcommand -a logs      -d "show or follow the run log"
complete -c disk-janitor -f -n __fish_use_subcommand -a config    -d "print the config file path and contents"
complete -c disk-janitor -f -n __fish_use_subcommand -a version   -d "print version"
complete -c disk-janitor -f -n __fish_use_subcommand -a help      -d "show help"

# per-subcommand flags
complete -c disk-janitor -n "__fish_seen_subcommand_from install"   -l with-agent-guidance -d "manage worktree guidance in agent config files"
complete -c disk-janitor -n "__fish_seen_subcommand_from install"   -l dry-run -d "preview only"
complete -c disk-janitor -n "__fish_seen_subcommand_from uninstall" -l purge -d "also remove cargo-sweep and app state"
complete -c disk-janitor -n "__fish_seen_subcommand_from run"       -l dry-run -s n -d "report candidates, delete nothing"
complete -c disk-janitor -n "__fish_seen_subcommand_from logs"      -s f -d "follow the log"
