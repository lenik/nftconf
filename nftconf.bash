# bash completion for nftconf

_nftconf()
{
	local cur prev words cword
	_init_completion || return

	local cmds="load unload status check show daemon stop convert help"
	local globals="-v --verbose -q --quiet -h --help --version"
	local conflict="-f --force -n --no-clobber --dry-run"

	# Global flags may appear anywhere; complete them when cur starts with -
	# after we know the subcommand context.

	local cmd="" i
	for ((i = 1; i < cword; i++)); do
		case ${words[i]} in
			load|unload|status|check|show|daemon|stop|convert|help)
				cmd=${words[i]}
				break
				;;
		esac
	done

	case $prev in
		--pid|-o|--output)
			_filedir
			return
			;;
	esac

	if [[ -z $cmd ]]; then
		if [[ $cur == -* ]]; then
			COMPREPLY=($(compgen -W '$globals' -- "$cur"))
		else
			COMPREPLY=($(compgen -W '$cmds' -- "$cur"))
		fi
		return
	fi

	case $cmd in
		load|unload|convert|daemon)
			if [[ $cur == -* ]]; then
				local opts="$globals $conflict"
				[[ $cmd == daemon || $cmd == stop ]] && opts+=" --pid"
				[[ $cmd == convert ]] && opts+=" -o --output"
				COMPREPLY=($(compgen -W '$opts' -- "$cur"))
			else
				_filedir
			fi
			;;
		status|check|show)
			if [[ $cur == -* ]]; then
				COMPREPLY=($(compgen -W '$globals' -- "$cur"))
			else
				_filedir
			fi
			;;
		stop)
			if [[ $cur == -* ]]; then
				COMPREPLY=($(compgen -W '$globals --pid' -- "$cur"))
			else
				_filedir
			fi
			;;
		help)
			COMPREPLY=()
			;;
		*)
			_filedir
			;;
	esac
}

complete -F _nftconf nftconf
