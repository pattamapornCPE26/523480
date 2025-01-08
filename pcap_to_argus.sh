#!/bin/bash

PCAP_FOLDER="/home/os/Desktop/project/New_Files/pcap/attack"
OUTPUT_FOLDER="/home/os/Desktop/project/New_Files/argus/attack"

# Create the output folder if it does not already exist.
mkdir -p "$OUTPUT_FOLDER"

for PCAP_FILE in "$PCAP_FOLDER"/*.pcap; do
    if [ -f "$PCAP_FILE" ]; then
        FILE_NAME="$(basename -- "$PCAP_FILE" .pcap)"
        ARGUS_FILE="$OUTPUT_FOLDER/${FILE_NAME}.argus"
        
         echo $ESCAPED_FILE_NAME

        echo "Converting $PCAP_FILE to $ARGUS_FILE"
        argus -r "$PCAP_FILE" -w "$ARGUS_FILE"

        if [ $? -ne 0 ]; then
            echo "Error converting $PCAP_FILE"
        fi
    else
        echo "No .pcap files found in $PCAP_FOLDER"
    fi

done