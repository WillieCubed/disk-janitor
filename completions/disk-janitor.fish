# fish completion for the normal job API
complete -c disk-janitor -f -n __fish_use_subcommand -a submit -d 'Submit a new command'
complete -c disk-janitor -f -n __fish_use_subcommand -a status -d 'Inspect jobs and capacity'
complete -c disk-janitor -f -n __fish_use_subcommand -a logs -d 'Read job output'
complete -c disk-janitor -f -n __fish_use_subcommand -a wait -d 'Wait for terminal outcome'
complete -c disk-janitor -f -n __fish_use_subcommand -a cancel -d 'Cancel your job'
complete -c disk-janitor -n '__fish_seen_subcommand_from status' -l json -d 'Machine-readable status'
complete -c disk-janitor -n '__fish_seen_subcommand_from logs' -s f -l follow -d 'Follow output'
