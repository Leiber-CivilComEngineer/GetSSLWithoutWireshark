#!/bin/bash

if [ -z "$1" ]; then
  echo "Please provide pcap file path"
  exit 1
fi

g++ getSSL.cpp -o getSSL -lpcap 
./getSSL $1 > 1.txt

g++ -std=c++17 analyze_txt.cpp -o analyze_txt
./analyze_txt