#!/bin/bash

echo "Initializing Pack Adoption..."

# Check dependencies exist
dependencies=("git" "demisto-sdk")

echo "Validating we have everything to get started..."
for d in "${dependencies[@]}"; do
	if ! command -v "$d" &> /dev/null
	then
		echo "'$d' could not be found. Please install it, reload the shell and try again. Exiting..."
		exit 1
	fi
done

echo "✓ Dependencies found."

# Check that we're a git repo
inside_git_repo="$(git rev-parse --is-inside-work-tree 2>/dev/null)"
if [ "$inside_git_repo" ]; then
  repo_root="$(git rev-parse --show-toplevel)"
  echo "✓ Found git repository in '$repo_root'. Changing directory into it."
  cd "$repo_root" || exit 1
  
else
  echo "✗ git repo cannot be found in current work tree."
  echo "Make sure that you're running this script from within the content repository path"
  exit 1
fi


# Check that we're on master/main
branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" != "master" ] && [ "$branch" != "main" ]; then
  echo "✗ Not on master/main branch.";
  untracked_files=$(git ls-files --other --directory --exclude-standard | wc -l | tr -d '[:space:]')

  # Check if there are any untracked files
  if [ "$untracked_files" -gt 0 ]; then
	echo "✗ Cannot checkout master/main branch since there are $untracked_files untracked files."
	echo "Please run 'git stash/revert' and rerun."
	exit 1

  else
	echo "No untracked changes done, attempting to change to master/main branch..."
	if git show-ref --quiet refs/heads/master; then
		git checkout master
	elif git show-ref --quiet refs/heads/main; then
		git checkout main
	
	current_branch="$(git rev-parse --abbrev-ref HEAD)"
	echo "✓ Changed to '$current_branch'"
	fi
	

  fi

else
  echo "✓ On '$branch' branch"
fi