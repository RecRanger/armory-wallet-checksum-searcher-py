import lz4.frame
import hashlib
import os
from datetime import datetime, timedelta
from tqdm import tqdm
from pathlib import Path
import argparse

from loguru import logger

# A tool to crawl through key-sized chunks of a file (32-bytes, roughly),
# calculate the checksum hash of that chunk, and see if it matches the following 4 bytes
# on disk. This is the format that Armory Wallets use to store their most important data,
# so we're search it. Best case, it will tell use the value of the ChainCode and PrivKey.

start_datetime = datetime.now()
start_datetime_str = start_datetime.strftime("%Y-%m-%d_%H-%M-%S")

BLOCK_SIZE_BYTES = 2**20 * 10
CHECKSUM_LEN = 4
CHUNK_TO_HASH_LEN = 32
### Options for CHUNK_TO_HASH_LEN ###
# 20 for Address
# 16 for Initialization Vector (IV)
# 32 for ChainCode and PrivKey [most valuable, and 2-for-1 as far as effort goes]
# 44 for v1 KDF Parameters
# 65 for PubKey

logger.info(f"Start time: {start_datetime_str}")
logger.info(f"Chunk size: {CHUNK_TO_HASH_LEN} bytes")
logger.info(f"Checksum size: {CHECKSUM_LEN} bytes")

def sha256(bits: bytes) -> bytes:
   return hashlib.new('sha256', bits).digest()

def hash256(s: bytes) -> bytes:
   """ Double-SHA256 """
   return sha256(sha256(s))

def computeChecksum(bytes_to_check: bytes, nBytes: int, hashFunc=hash256) -> bytes:
   return hashFunc(bytes_to_check)[:nBytes]


def search_block_for_checksum(block: bytes) -> int:
    success_count = 0
    # Process each byte in the block up to the point where a full chunk plus checksum can no longer be read
    for i in range(min(len(block) - CHUNK_TO_HASH_LEN - CHECKSUM_LEN + 1, BLOCK_SIZE_BYTES - CHUNK_TO_HASH_LEN - CHECKSUM_LEN + 1)):
        chunk_to_hash_bytes = block[i:i + CHUNK_TO_HASH_LEN]
        read_checksum_bytes = block[i + CHUNK_TO_HASH_LEN:i + CHUNK_TO_HASH_LEN + CHECKSUM_LEN]
        hash_result = computeChecksum(chunk_to_hash_bytes, CHECKSUM_LEN)
        
        # Compare the hash result to the next 4 bytes
        if hash_result == read_checksum_bytes:
            logger.info(f"====== BIG WIN! SUCCESS! It matches. ======")
            logger.info(f"Hash: {hash_result.hex()}, chunk_to_hash_bytes: {chunk_to_hash_bytes.hex()}")
            success_count += 1

    return success_count


def check_hashes_in_file(file_path: str):
    # Determine if the file is compressed based on the .lz4 extension
    if file_path.endswith(".lz4"):
        open_func = lz4.frame.open  # Use LZ4 open function for lz4 files
        logger.info("File is compressed with LZ4")
        estimated_uncompressed_size = os.stat(file_path).st_size * 2
    else:
        open_func = open  # Use regular open for uncompressed files
        logger.info("File is uncompressed")
        estimated_uncompressed_size = os.stat(file_path).st_size
    
    file_start_time = datetime.now()
    last_log_time = datetime.now()
    total_file_size = os.stat(file_path).st_size
    success_count = 0

    with open_func(file_path, "rb") as fd, tqdm(total=estimated_uncompressed_size, unit=" bytes", unit_scale=True, desc=f"Searching {Path(file_path).name}") as pbar:
        while True:
            block = fd.read(BLOCK_SIZE_BYTES)
            if not block:
                logger.info(f"Reached end of file at {fd.tell()} bytes")
                break  # End of file

            assert isinstance(block, bytes)
            
            result_count = search_block_for_checksum(block)
            success_count += result_count

            if result_count > 0:
                logger.info(f"Found {result_count} matches in block starting at {fd.tell():,} bytes")
                logger.info(f"File position: {fd.tell()/1024/1024:,} / {total_file_size/1024/1024:,} MiB = {fd.tell() / total_file_size:.2%}")
                logger.info(f"Success count: {success_count}")
                logger.info(f"File path: {file_path}")
            
            # Move back 23 bytes to shift the window by one byte
            fd.seek(-CHUNK_TO_HASH_LEN - CHECKSUM_LEN - 10, 1)

            pbar.update(len(block))

            # Log progress
            if datetime.now() - last_log_time > timedelta(seconds=45):
                bytes_per_sec = fd.tell() / (datetime.now() - file_start_time).total_seconds()
                logger.info(f"File position: {fd.tell()/1024/1024:,.1f} / {total_file_size/1024/1024:,.1f} MiB = {fd.tell() / total_file_size:.2%} @ {int(bytes_per_sec):,} bytes/sec. {success_count=}")
                last_log_time = datetime.now()

    # Log completion
    logger.info(f"File check complete at {fd.tell()} bytes: {file_path}")
    logger.info(f"File check complete in {(datetime.now() - file_start_time).total_seconds():.2f} seconds.")

def run_all_images_in_dir():
    file_path_list = """
<path_list_goes_here>
""".strip().splitlines()

    # Drive_Rat/Rat_whole_img2.img.lz4 -> ignore

    for file_path in file_path_list:
        logger.info(f"Checking file: {file_path} (size: {os.stat(file_path).st_size:,} bytes)")
        check_hashes_in_file(file_path)

        logger.info(f"Done with file: {file_path} (size: {os.stat(file_path).st_size:,} bytes)")

def main():
    # parse args
    parser = argparse.ArgumentParser(description='Crawl for checksums in files.')
    parser.add_argument('-f', '--file', help='Input image file (.img or .img.lz4) to search')
    parser.add_argument('-o', '--output', help='Output file to write the results to. Must end in .log.')
    args = parser.parse_args()

    assert args.output.endswith(".log")
    logger.add(args.output)

    logger.info(f"Started logging to file. Start time: {datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}")

    if args.file:
        logger.info(f"Checking file: {args.file} (size: {os.stat(args.file).st_size:,} bytes)")
        check_hashes_in_file(args.file)
    else:
        logger.info("Checking files in the in-code images directory")
        run_all_images_in_dir()

if __name__ == "__main__":
    main()
