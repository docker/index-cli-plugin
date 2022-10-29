#!/bin/bash
#written by rezshar
#The easiest way to scan all local images
./docker-index 2>&1 > /dev/null
Val1=$(echo $?)
   if [ "$?" -ne 0 ]
   then
      echo "Installing docker-index"
      echo "please wait ..."
      ./install.sh
#    else
#       echo "OK!"
   fi

if [ ! -d /var/lib/docker/image/overlay2/imagedb/content/sha256/ ]; then
DOCKERPATH=$(docker info  |  grep "Docker Root Dir" | sed 's/^.*: //')
ls $DOCKERPATH/image/overlay2/imagedb/content/sha256/ -1 > temp
else
ls /var/lib/docker/image/overlay2/imagedb/content/sha256/ -1 > temp
fi

file="temp"
while read -r line
do
    printf 'Line: %s\n' "$line"
    current=$line
echo "Scanning $current"
./docker-index cve --image $current DSA-2022–0001
#echo "Lets go for another Images :)"
done < $file
echo "Enjoy"
