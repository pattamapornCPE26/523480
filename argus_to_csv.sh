#!/bin/bash

input_dir="/home/os/Desktop/project/New_Files/argus/attack"
output_dir="/home/os/Desktop/project/New_Files/csv/attack/pcap"

cd "$input_dir" || exit

for argus_file in *.argus; do

  output_file="${argus_file%.argus}.csv"
  full_output_path="$output_dir/$output_file"

  # Check if the .csv file to be created already exists.
  if [ -f "$full_output_path" ]; then
    echo "File $output_file already exists. Skipping conversion."
  else
    # use ra -r for convert .argus to .csv
    ra -r "$argus_file" -s dur proto sttl dttl spkts dpkts sbytes dbytes sload dload sloss dloss sintpkt dintpkt sjit djit state swin dwin stcpb dtcpb tcprtt synack ackdat smeansz dmeansz -c, > "$full_output_path"
    echo "Converted $argus_file to $output_file"
  fi
done