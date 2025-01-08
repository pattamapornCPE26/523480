#!/bin/bash

read -p "Enter your file name: " BASE_FILENAME

OUTPUT_FILE_ENP0S3="${BASE_FILENAME}.pcap"
OUTPUT_HOST="${BASE_FILENAME}.atop"

PATH_HOST="/home/os/Desktop/project/New_Files/host/attck"
PATH_LOG="/home/os/Desktop/project/New_Files/host/attck/text_log"
S_DIR="$PATH_LOG/CPU"
D_DIR="$PATH_LOG/DISK"
M_DIR="$PATH_LOG/MEM"

# Start capturing network packets with tshark
tshark -i enp0s3 -w "/home/os/Desktop/project/New_Files/pcap/attack/$OUTPUT_FILE_ENP0S3" &
Tshark_PID_ENP0S3=$!

# Start recording system activity with atop
sudo atop -w "$PATH_HOST/$OUTPUT_HOST" &
Host_PS=$!

echo "Capturing... Press 'stop' to end."

# Loop to monitor user input to stop capturing
while true; do
    read -p "Enter 'stop' to end: " user_input
    if [[ "$user_input" == "stop" ]]; then
        kill $Tshark_PID_ENP0S3
        sudo kill $Host_PS
        echo "Capturing stopped and results saved."

        # Process the captured atop file
        if [ -f "$PATH_HOST/$OUTPUT_HOST" ]; then
            base_name="${OUTPUT_HOST%.*}"
            output_file_s="${base_name}_s.txt"
            output_file_d="${base_name}_d.txt"
            output_file_m="${base_name}_m.txt"

            # Generate output files with atop commands
            atop -r "$PATH_HOST/$OUTPUT_HOST" -s > "$S_DIR/$output_file_s"
            atop -r "$PATH_HOST/$OUTPUT_HOST" -d -L 50 > "$D_DIR/$output_file_d"
            atop -r "$PATH_HOST/$OUTPUT_HOST" -m -L 150 > "$M_DIR/$output_file_m"

            echo "Converted $OUTPUT_HOST to:"
            echo "  - $output_file_s"
            echo "  - $output_file_d"
            echo "  - $output_file_m"
        else
            echo "File $OUTPUT_HOST does not exist."
        fi

        break
    fi

done
