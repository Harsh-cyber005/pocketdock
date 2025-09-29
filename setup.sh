#!/bin/bash

echo "Including $1 into the jail"

if [ -z "$1" ]; then
    echo "Usage: ./setup.sh <program_path>"
    exit 1
fi

jailRoot="/home/ubuntu/my-jail"
jailBin="$jailRoot/bin"

mkdir -p "$jailBin"

echo "copying $1 into the jail"
cp -p "$1" "$jailBin/"

mapfile -t depArray < <(ldd "$1" | awk '{print $3}' | grep -v '^$')

for i in "${depArray[@]}"; do
    src="$i"
    destDir="$jailRoot$(dirname "$i")"

    mkdir -p "$destDir"
    cp -p "$src" "$destDir/"

    echo "copied $src -> $destDir/"
done
