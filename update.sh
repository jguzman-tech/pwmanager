#!/bin/bash

if [ "$#" -eq 2 ]
then
    address="$1"
    new_value="$2"
    mysql --execute="UPDATE inf639.pwmanager SET value = '${new_value}'
WHERE address = '${address}'"
else
    echo "illegal number of parameters, aborting..."
fi
