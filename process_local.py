import os
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the required function verbatim from api_builder.py
from api_builder import process_cve

def process_single_cve(cve_id: str, output_parent_dir: str):
    """
    Worker function to process a single CVE ID concurrently.
    """
    cve_id = cve_id.strip()
    if not cve_id:
        return

    # Extract the year from the CVE string (e.g., CVE-2021-44228 -> 2021)
    parts = cve_id.split('-')
    if len(parts) >= 3 and parts[0].upper() == 'CVE':
        year = parts[1]
    else:
        print(f"Skipping malformed CVE ID: {cve_id}")
        return

    try:
        local_repos_copy = "./repos"
        
        json_output = process_cve(
            cve_id, 
            base_repos=local_repos_copy
        )
        
        # Create the year directory if it doesn't exist
        year_dir = os.path.join(output_parent_dir, year)
        os.makedirs(year_dir, exist_ok=True)
        
        # Save the JSON string to the target file
        output_file_path = os.path.join(year_dir, f"{cve_id}.json")
        with open(output_file_path, 'w', encoding='utf-8') as out_f:
            out_f.write(json_output)
            
        print(f"Successfully saved {cve_id} to {output_file_path}")

    except Exception as e:
        print(f"Error processing {cve_id}: {e}")

def process_bulk_cves(input_file: str, output_parent_dir: str = ".", max_workers: int = 10):
    """
    Reads CVEs from a text file and processes them concurrently using threads.
    """
    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        cve_list = [line.strip() for line in f if line.strip()]

    total = len(cve_list)
    print(f"Starting processing for {total} CVEs using {max_workers} worker threads...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks to the thread pool
        future_to_cve = {
            executor.submit(process_single_cve, cve_id, output_parent_dir): cve_id 
            for cve_id in cve_list
        }
        
        # Track completion as threads finish
        for index, future in enumerate(as_completed(future_to_cve), start=1):
            cve_id = future_to_cve[future]
            try:
                future.result()
            except Exception as e:
                print(f"Unhandled exception for {cve_id}: {e}")
            print(f"Progress: [{index}/{total}] completed.")

if __name__ == "__main__":
    input_txt_file = "./all_cves.txt"
    parent_directory = "."
    
    # Adjust max_workers as needed depending on I/O vs network limits
    process_bulk_cves(input_txt_file, parent_directory, max_workers=10)