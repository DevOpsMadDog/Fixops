#!/bin/bash
mkdir -p /tmp/deepwiki
cd /tmp/deepwiki
rm -rf *
unzip -o ~/Downloads/DevOpsMadDog-Fixops-DeepWiki.zip
echo "=== FILES ==="
find . -type f -name '*.md' | sort
echo "=== COUNT ==="
find . -type f -name '*.md' | wc -l

