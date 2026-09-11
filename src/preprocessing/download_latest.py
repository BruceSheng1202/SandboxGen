#!/usr/bin/env python3
"""
MALWARE SAMPLE DOWNLOADER
Downloads 5 recent samples from each family and organizes by year.

Requires the MALWAREBAZAAR_API_KEY environment variable to be set:
    export MALWAREBAZAAR_API_KEY=<your key>
"""

import requests
import json
import os
from datetime import datetime

# Configuration
AUTH_KEY = os.environ["MALWAREBAZAAR_API_KEY"]
API_URL = "https://mb-api.abuse.ch/api/v1/"
REQUEST_TIMEOUT = 30  # seconds
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200MB — DATA-03 zip/response-bomb cap


def _read_capped(response, max_bytes=MAX_DOWNLOAD_BYTES):
    """Stream a response body, aborting once it exceeds max_bytes."""
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(
                f"response body exceeded {max_bytes} byte cap "
                f"(aborted after {total} bytes)"
            )
        chunks.append(chunk)
    return b"".join(chunks)

# Define the 10 families found on MalwareBazaar
families = [
    "Kovter",
    "Gootloader",
    "SocGholish",
    "RaspberryRobin",
    "Astaroth",
    "NetWalker",
    "GuLoader",
    "Latrodectus",
    "BazarLoader",
    "Emotet"
]

# Get today's date
today = datetime.now().strftime("%Y-%m-%d")

# Create main folder with date in current working directory
main_folder = os.path.join(os.getcwd(), f"Malware_Samples_{today}")
os.makedirs(main_folder, exist_ok=True)

print(f"Main folder created at: {main_folder}\n")


def download_sample(sha256, output_path):
    """Download a single sample by SHA256 hash"""
    headers = {"Auth-Key": AUTH_KEY}
    data = {"query": "get_file", "sha256_hash": sha256}

    try:
        response = requests.post(API_URL, headers=headers, data=data,
                                 timeout=REQUEST_TIMEOUT, stream=True)
        response.raise_for_status()
        try:
            # DATA-03 fix: read the body through a capped streaming reader
            # instead of buffering an unbounded response.content — a
            # malicious/compromised response can no longer exhaust memory
            # or disk before we've even inspected it.
            content = _read_capped(response)
        finally:
            response.close()

        # Try to parse as JSON to check for errors
        try:
            result = json.loads(content)
            # If we can parse JSON, it's an error response
            if result.get("query_status") and result.get("query_status") != "ok":
                print(f"      API Error: {result.get('query_status')}")
                return False
            else:
                # If JSON parsed but has data, it might be a success with JSON
                if result.get("data"):
                    import base64
                    file_data = base64.b64decode(result["data"])
                    if len(file_data) > MAX_DOWNLOAD_BYTES:
                        print(f"      Error: decoded payload exceeds "
                              f"{MAX_DOWNLOAD_BYTES} byte cap")
                        return False
                    with open(output_path, "wb") as f:
                        f.write(file_data)
                    return True
                return False
        except (ValueError, json.JSONDecodeError):
            # Not JSON - expected to be the ZIP archive itself. Verify the
            # ZIP magic bytes rather than trusting ">100 bytes and not
            # JSON" (DATA-05/DATA-08) — a proxy error page or truncated
            # response could otherwise be silently saved as a "successful"
            # download. Note: this only verifies the outer ZIP container;
            # verifying the inner sample's own sha256 requires extracting
            # it with the abuse.ch password, which download_samples.sh
            # already does — this simple per-family downloader does not
            # extract, so it stops at container-level integrity.
            if content[:4] != b"PK\x03\x04":
                print(f"      Error: response is not a valid ZIP "
                      f"({len(content)} bytes, bad magic)")
                return False
            with open(output_path, "wb") as f:
                f.write(content)
            return True

    except Exception as e:
        print(f"      Download error: {e}")
        return False


total_downloaded = 0
total_failed = 0

for family in families:
    print(f"=== Processing: {family} ===")

    headers = {"Auth-Key": AUTH_KEY}
    data = {"query": "get_taginfo", "tag": family.lower()}

    try:
        response = requests.post(API_URL, headers=headers, data=data,
                                 timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result = response.json()

        if result.get("query_status") != "ok":
            print(f"  No samples found")
            total_failed += 1
            continue

        samples = result.get("data", [])
        if len(samples) == 0:
            print(f"  No samples found")
            total_failed += 1
            continue

        # Take only the first 5 samples
        first_five = samples[:5]
        count = 0

        for sample in first_five:
            count += 1
            sha256 = sample.get("sha256_hash")
            original_name = sample.get("file_name", "unknown")
            first_seen = sample.get("first_seen", "")

            # Extract year from first_seen
            if first_seen and len(first_seen) >= 4:
                year = first_seen[:4]
            else:
                year = "Unknown"

            # Create year subfolder inside family folder
            family_folder = os.path.join(main_folder, family)
            year_folder = os.path.join(family_folder, year)
            os.makedirs(year_folder, exist_ok=True)

            # Clean filename for safe saving
            safe_name = "".join(c for c in original_name if c.isalnum() or c in "._- ")
            if not safe_name:
                safe_name = f"sample_{count}"

            output_filename = f"sample_{count}_{safe_name}.zip"
            output_path = os.path.join(year_folder, output_filename)

            print(f"  Downloading sample {count}/5: {original_name} ({year})")

            if download_sample(sha256, output_path):
                file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                print(f"    Saved: {family}/{year}/{output_filename} ({file_size} bytes)")
                total_downloaded += 1
            else:
                print(f"    Download failed")
                total_failed += 1

        print(f"  Completed: {family} ({count} samples)\n")

    except Exception as e:
        print(f"  Error processing {family}: {e}")
        total_failed += 1

# Summary
print("=" * 50)
print("DOWNLOAD COMPLETE")
print("=" * 50)
print(f"Total samples downloaded: {total_downloaded}")
print(f"Total failures: {total_failed}")
print(f"Location: {main_folder}")
print(f"All ZIP files password: infected")
print("")

# Show folder structure
print("Folder structure:")
for family in families:
    family_path = os.path.join(main_folder, family)
    if os.path.exists(family_path):
        print(f"  {family}/")
        for year in sorted(os.listdir(family_path)):
            year_path = os.path.join(family_path, year)
            if os.path.isdir(year_path):
                zip_count = len([f for f in os.listdir(year_path) if f.endswith('.zip')])
                print(f"    {year}/ ({zip_count} samples)")
