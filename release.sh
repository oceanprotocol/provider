#!/bin/bash

usage(){
  echo "Usage: $0 {major|minor|patch} [--tag]"
  exit 1
}

if [ "$#" -lt 2 ]; then
    echo "Illegal number of parameters"
    usage
elif [[ $1 != 'major' && $1 != 'minor' && $1 != 'patch' ]]; then
    echo 'First argument must be {major|minor|patch}'
    usage
fi

echo 'Generating changelog for version:'$2

git checkout -b feature/bumpversion-to-v$2

sh bumpversion.sh $1

changes="$(git log main..feature/bumpversion-to-v$2 --format=%s --no-merges --invert-grep --grep="Generate changelog for release" | awk '{print "- " $0}')"

touch CHANGELOG.md

echo '#### v'$2$'\n' >> CHANGELOG.md
echo "> $(date +\"%d-%B-%Y\")" >> CHANGELOG.md
echo "$changes"$'\n' >> CHANGELOG.md

git add CHANGELOG.md
git commit -m "Generate changelog for release v"$2

git checkout -