#!/bin/bash

for i in $(cat headers.txt); do
  mv $i $i.bak
  touch $i
  make clean
  make -j10
  if [ $? -eq 0 ]; then
    echo $i >> not_needed.txt
  fi
  mv $i.bak $i
done