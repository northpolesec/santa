#!/bin/bash
set -exo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

find ${GIT_ROOT} \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec clang-format --Werror --dry-run {} \+

! git grep -EIn $'[ \t]+$' -- ':(exclude)*.patch'

go install github.com/bazelbuild/buildtools/buildifier@latest
~/go/bin/buildifier --lint=warn -r ${GIT_ROOT}

if command -v virtualenv &> /dev/null
then
    echo ""
else
    echo "virtualenv not found. Installing..."
    sudo pip3 install virtualenv
    if [ $? -eq 0 ]; then
        echo "virtualenv has been successfully installed"
    else
        echo "Failed to install virtualenv"
        exit 1
    fi
fi

virtualenv ./venv
source ./venv/bin/activate
python3 -m pip install -q pyink
python3 -m pyink --config ${GIT_ROOT}/.pyink-config --check ${GIT_ROOT}
