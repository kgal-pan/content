#!/bin/bash

#######################################
# Check if we're running supported OS (darwin|linux)
# Globals:
#   None
# Arguments:
#   None
#######################################
detect_os() {

	os=$(uname -s)

	if [ "$os" == "Darwin" ]; then
		echo "Mac OS"
	elif [ "$os" == "Linux" ]; then
		echo "$os"
	else
		echo "✗ Unsupported OS. Terminating"
		exit 1
	fi


}

#######################################
# Verify dependencies exist
# Globals:
#   None
# Arguments:
#   dependencies: array of dependencies
#######################################
check_dependencies(){

	dependencies=$1

	for d in "${dependencies[@]}"; 
	do
		if ! command -v "$d" &> /dev/null
		then
			echo "'$d' could not be found. Please install it, reload the shell and try again. Exiting..."
			exit 1
		else
			echo "✓ Dependency '$d' found."
		fi
	done

}

#######################################
# Verify we're in the content repo
# Globals:
#   None
# Arguments:
#   None
#######################################
get_repo_root(){
	inside_git_repo="$(git rev-parse --is-inside-work-tree 2>/dev/null)"
	if [ "$inside_git_repo" ]; then
		repo_root="$(git rev-parse --show-toplevel)"
		echo "$repo_root"
	else
		echo "✗ git repo cannot be found in current work tree."
		echo "Make sure that you're running this script from within the content repository path"
		exit 1
	fi
}

#######################################
# Verify Pack exists
# Globals:
#   None
# Arguments:
#   pack_name: The name of the Pack from argument
#   repo_root: The root git repository path
#######################################
verify_pack_exists(){
	# Check if pack exists
	pack_name=$1
	root_repo=$2
	dir="$root_repo/Packs/$pack_name"

	if [ ! -d "$dir" ] 
	then
		echo "✗ Cannot find Pack name '$pack_name' in directory '$dir'" 
		exit 1
	fi
}


#######################################
# Create new branch
# Globals:
#   pack_name
# Arguments:
#   None
#######################################
create_adopt_branch(){
	branch_name="partner-$pack_name-adopt-start"
	git checkout -q -b "$branch_name"
	echo "✓ Created new branch for adoption '$branch_name'"
}


#######################################
# Create new branch from master
# Globals:
#   os: the string representing the operating system
# Arguments:
#   None
#######################################
create_branch_from_head(){
	# Check that we're on master/main
	# If on master/main, create new adopt branch
	# If not, see if there are any untracked files and attempt to checkout master/main if none
	branch="$(git rev-parse --abbrev-ref HEAD)"
	if [ "$branch" != "master" ] && [ "$branch" != "main" ]; then
		echo "✗ Not on master/main branch.";
		untracked_files=$(git --no-pager  diff --name-only | wc -l | tr -d '[:space:]')
	
		# Check if there are any untracked files
		# If there are, terminate
		# If there aren't, attempt to checkout master/main
		if [ "$untracked_files" -gt 0 ]; then
			echo "✗ Cannot checkout master/main branch since there are $untracked_files untracked files:"
			git status | grep -i modified | cut -d ":" -f2
			echo "Please run 'git stash/revert/reset' and rerun."
			exit 1
		else
			echo "No untracked changes done, attempting to change to master/main branch..."
			if git show-ref --quiet refs/heads/master; then
				echo "Checking out master branch..."
				# TODO rm comment
				# git checkout master
			elif git show-ref --quiet refs/heads/main; then
				echo "Checking out main branch..."
				# TODO rm comment
				# git checkout main
			else
				echo "Could not find references to main/master HEAD. Terminating..."
				exit 1
			
			create_adopt_branch
			fi
		fi
		else
		echo "✓ On '$branch' branch"
		create_adopt_branch
	fi
}

#######################################
# Get formatted date for adoption according to OS
# Globals:
#   os: the string representing the operating system
# Arguments:
#   None
#######################################
get_move_date(){

	if [ "$os" == "Mac OS" ] 
	then
		date -v "+90d" "+%B %d, %Y"
	else
		date -d "+90 days" "+%B %d, %Y"
	fi
	
}

#######################################
# Append adoption message to top of README.md 
# Globals:
#   None
# Arguments:
#   readme: the path to the Pack README.md
#   message: the message to write to the top of the README.md
#######################################
add_msg_to_readme(){

	readme=$1
	message=$2

	if [ "$os" == "Mac OS" ] 
	then
		sed -i '' "1s/^/$message\n\n/g" "$readme"
	else
		sed -i "1s/^/$message\n\n/" "$readme"
	fi

}


#######################################
# Perform adoption start steps mentioned in https://xsoar.pan.dev/docs/partners/adopt#process
# 1) Add message to README
# 2) Bump version
# 3) Create release notes and add message there
# Globals:
#   dir
# Arguments:
#   None
#######################################
adopt_start() {
	message=$(echo "Note: Support for this Pack will be moved to Partner starting $(get_move_date).")
	readme="$dir/README.md"

	add_msg_to_readme "$readme" "$message"

}


main(){
	# Check that an argument was passed
	[ $# -ne 1 ] && { echo "Usage: $0 PACK_NAME"; exit 1; }
	pack_name=$1

	echo "Initializing Pack Adoption..."

	os=$(detect_os)
	echo "✓ Detected OS '$os'."

	dependencies=("git" "demisto-sdk")
	check_dependencies "${dependencies[@]}"
	echo "✓ All dependencies met."

	root_repo=$(get_repo_root)
	echo "✓ Found git repository in '$root_repo'."

	verify_pack_exists "$pack_name" "$root_repo"
	echo "✓ Pack '$pack_name' exists."

	# create_branch_from_head

}


main "$@"