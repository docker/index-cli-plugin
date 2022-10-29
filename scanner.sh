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
ls $DOCKERPATH -1 > .temp.
else
ls /var/lib/docker/image/overlay2/imagedb/content/sha256/ -1 > .temp.
fi
for p in (.temp.)
while read p; do
#   echo "$p"
echo "Scannnig $p"
./docker-index cve --image $p DSA-2022–0001
echo "Lets go for another Images :)"



done <.temp.
echo "Enjoy"