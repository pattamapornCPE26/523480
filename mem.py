import os
import csv

def determine_label_and_type(file_name):
    if "normal" in file_name.lower():
        return 0, "normal"
    elif "brute" in file_name.lower():
        return 1, "brute force"
    elif "nmap" in file_name.lower():
        return 1, "scanning"
    elif any(attack in file_name.lower() for attack in ["tcp", "udp", "icmp", "ack", "hping"]):
        return 1, "dos"
    elif "ddos" in file_name.lower():
        return 1, "ddos"
    elif "injection" in file_name.lower():
        return 1, "injection"
    elif "arp" in file_name.lower():
        return 1, "arp spoofing"
    elif "xss" in file_name.lower():
        return 1, "xss"
    else:
    	return "-", "unknow"

def extract_memory_snapshots_to_csv(file_path, output_file, label, type_):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    snapshots = []
    current_snapshot = None
    extracting_process = False
    process_count = 0

    for line in lines:
        # ตรวจจับ ATOP Header เพื่อดึง Timestamp
        if "ATOP - Linux" in line:
            if current_snapshot:
                snapshots.append(current_snapshot)
            timestamp = " ".join(line.split()[3:5])
            current_snapshot = {"timestamp": timestamp, "processes": []}
            extracting_process = False
            process_count = 0

        # เริ่มดึงข้อมูล process เมื่อเจอ "PID"
        elif "PID" in line:
            extracting_process = True
            process_count = 0
            continue

        # หยุดดึงข้อมูลเมื่อเจอบรรทัดว่าง
        elif line.strip() == "":
            extracting_process = False

        # ดึงข้อมูล process สูงสุด 10 แถว
        elif extracting_process and process_count < 10:
            process_details = line.strip().split()
            # ดึงเฉพาะคอลัมน์ที่ต้องการ
            if len(process_details) >= 10:  # ตรวจสอบว่ามีข้อมูลเพียงพอ
                selected_data = {
                    "PID": process_details[0],
                    "MINFLT": process_details[2],
                    "MAJFLT": process_details[3],
                    "VSTEXT": process_details[4],
                    "VSIZE": process_details[8],
                    "RSIZE": process_details[9],
                    "VGROW": process_details[11],
                    "RGROW": process_details[12],
                    "MEM": process_details[16],
                    "CMD": process_details[17],
                }
                current_snapshot["processes"].append(selected_data)
                process_count += 1

    # เพิ่ม Snapshot ชุดสุดท้าย
    if current_snapshot:
        snapshots.append(current_snapshot)

    # บันทึกข้อมูลลงไฟล์ CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # เขียนหัวข้อ
        writer.writerow(["PID", "MINFLT", "MAJFLT", "VSTEXT", "VSIZE", "RSIZE", "VGROW", "RGROW", "MEM", "CMD", "label", "type", "Timestamp"])

        for snapshot in snapshots:
            timestamp = snapshot["timestamp"]
            for process in snapshot["processes"]:
                # เพิ่มข้อมูลพร้อม Timestamp
                writer.writerow([
                    process["PID"], process["MINFLT"], process["MAJFLT"], process["VSTEXT"],
                    process["VSIZE"], process["RSIZE"], process["VGROW"], process["RGROW"],
                    process["MEM"], process["CMD"], label, type_, timestamp
                ])

    print(f"Extracted memory snapshots saved to {output_file}")

def process_multiple_files(input_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)  # สร้างโฟลเดอร์ output หากยังไม่มี

    for file_name in os.listdir(input_dir):
        if file_name.endswith(".txt"):
            input_file = os.path.join(input_dir, file_name)
            output_file = os.path.join(output_dir, f"{os.path.splitext(file_name)[0]}.csv")
            
            # ตรวจสอบ label และ type จากชื่อไฟล์
            label, type_ = determine_label_and_type(file_name)

            print(f"Processing file: {file_name} -> label: {label}, type: {type_}")
            extract_memory_snapshots_to_csv(input_file, output_file, label, type_)
            print("")

# ใช้งานฟังก์ชัน
process_multiple_files("/home/os/Desktop/project/New_Files/host/attck/text_log/MEM", "/home/os/Desktop/project/New_Files/csv/attack/host/mem")
