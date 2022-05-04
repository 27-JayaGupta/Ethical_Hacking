#!/bin/bash

for((i=1;i<=30;i++)); do
    declare -i j=0
    for((k=1;k<=10;k++));do
        filename=~/Downloads/medium-3/alohaSenpai$i/flagHere$k.txt 
        str="${str} {tail -c 2 $filename}"
        j=$j+1
        # echo $j
        # echo $filename
        tail -c 2 $filename >> a.txt
        if [ $j -eq 10 ]; then
            break
        fi 

echo $string
done
done