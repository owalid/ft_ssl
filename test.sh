#!/bin/bash

export C_RED=$(tput setaf 1)
export C_GREEN=$(tput setaf 2)
export C_BLUE=$(tput setaf 4)
export C_BOLD=$(tput bold)
export C_CLR=$(tput sgr0)

read data
echo -n "$C_RED"
./ft_ssl $1 -s "$data"
echo -n "$C_GREEN"
echo -n "$data" | openssl $1
echo -n "$C_CLR"