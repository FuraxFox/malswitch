#!/bin/bash
#
#

TARGET=http://127.0.0.1:8080/submission-queue

echo "submit text as TLP:RED"
curl -v -F "sample=@sample1.txt" -F "TLP=RED" "$TARGET"
sleep 1

echo "submit binary as TLP:CLEAR"
curl -v -F "sample=@sample2.bin" -F "TLP=CLEAR" "$TARGET"
sleep 1

echo "submit text with wrong TLP:PINK"
curl -v -F "sample=@sample3.txt" -F "TLP=PINK" "$TARGET"

echo "done."

