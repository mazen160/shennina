#!/usr/bin/env bash
(which nmap && which msfconsole && which msfrpcd && which docker && which python3 && which pip3)
if [[ $? != 0 ]]; then
  echo "Pre-requirements are missing."
  exit 1
else
  echo "Pre-requirements are fulfilled."
  exit 0
fi
