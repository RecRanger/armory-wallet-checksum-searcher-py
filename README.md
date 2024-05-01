# armory-wallet-checksum-searcher-py
A tool to locate Armory wallets on corrupted hard drives, hard drives where the wallet was deleted, etc.

**⚠️⚠️ This repository is deprecated. Please [use my alternative Rust version](https://github.com/RecRanger/armory-wallet-checksum-searcher) instead.⚠️⚠️**

## Usage

```bash
cd crawl_for_checksums_py
python3 crawl_for_checksums.py -f input_file.img -o ./output_log.log
sudo python3 crawl_for_checksums.py -f /dev/sda -o ./output_log.log
```
