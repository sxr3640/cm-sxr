#!bin/bash
while read -r str
do
#len=$[${#str}-1]
#echo $len
#str=${str:0:len}
#echo $str|cut -c1-$len
  sudo ./tunneltrace -h 2402:4e00::2 $str > tunAna1/$str.txt&&echo $str
  done<ipv6add1.txt
