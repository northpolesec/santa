#!/bin/bash
set -exo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

find ${GIT_ROOT} \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec clang-format --Werror --dry-run {} \+

! git grep -EIn $'[ \t]+$' -- ':(exclude)*.patch'

go install github.com/bazelbuild/buildtools/buildifier@latest
~/go/bin/buildifier --lint=warn -r ${GIT_ROOT}

if [ -d "./santa-venv" ]; then
 echo "santa-venv already exists reusing"
else
 echo "Creating virtual environment ./santa-venv..."
    python3 -m venv ./santa-venv
    if [ $? -eq 0 ]; then
        echo "Virtual environment ./santa-venv has been successfully created"
    else
        echo "Failed to create virtual environment ./santa-venv"
        exit 1
    fi
fi

source ./santa-venv/bin/activate
python3 -m pip install -q pyink
python3 -m pyink --config ${GIT_ROOT}/.pyink-config --check ${GIT_ROOT}
