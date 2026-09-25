# recursive-unzip

A Python script that automatically unpacks **nested ZIP archives** — the classic "a ZIP inside a ZIP inside a ZIP, with an unknown number of layers" situation often seen in CTF challenges, forensics tasks, and messy downloaded archives.

Just run the script, drag the outermost ZIP into the terminal, and it will keep extracting layer after layer until only the final non-ZIP files remain.

## Features

- **True recursive expansion** — uses a queue instead of a single follow-chain, so when one archive contains multiple inner ZIPs, **every branch** is extracted, not just the last entry.
- **Automatic password guessing**, tried in order:
  1. no password
  2. the archive's own filename (with/without extension, lowercased, uppercased, reversed)
  3. the filenames of the inner ZIP entries (a common CTF pattern)
  4. a built-in list of common weak passwords (easy to extend)
- **Magic-byte detection** — identifies archives by the `PK` file header rather than the `.zip` extension, so extension-less files and files disguised as images are handled correctly.
- **Chinese filename repair** — restores garbled names caused by ZIP entries missing the UTF-8 flag (the classic Windows cp437/GBK mojibake).
- **Chinese password support** — non-ASCII passwords are attempted with both UTF-8 and GBK encoding.
- **Optional AES support** — install `pyzipper` to handle WinZip AES-encrypted archives, which the standard library cannot open.
- **Safe by design** — original archives are **never deleted** by default; each layer extracts into its own numbered folder under `_extracted/`, and same-name files at different layers never overwrite each other.
- Clear per-file logging showing which file was extracted and which password worked.

## Requirements

- Python 3.7+
- No third-party package is required for ordinary (ZipCrypto) or unencrypted ZIPs.
- Optional: install `pyzipper` if you may encounter AES-encrypted archives:

```bash
pip install pyzipper
```

## Usage

Run the script and paste or drag the target ZIP file into the terminal window:

```bash
python recursive_unzip.py
```

````
Enter the path to the ZIP file (you can drag and drop it into this window): D:\ctf\challenge\outer.zip
[1] Extracting: D:\ctf\challenge\outer.zip
    -> D:\ctf\challenge\_extracted\001_outer
    [+] inner.zip  (password: outer)
[2] Extracting: D:\ctf\challenge\_extracted\001_outer\inner.zip
    -> D:\ctf\challenge\_extracted\002_inner
    [+] flag.txt  (no password)

=== Recursion finished. Final files (non-ZIP) ===
  D:\ctf\challenge\_extracted\002_inner\flag.txt
````

All extracted content is placed in an `_extracted/` directory next to the input file, organized into numbered subfolders (`001_...`, `002_...`, one per archive) so the nesting structure stays easy to follow.

## How It Works

1. The input file is added to a processing queue.
2. A file is inspected for the `PK` magic header.
   - If it is not a ZIP, it is recorded as a **final file**.
   - If it is a ZIP, all of its entries are extracted into a dedicated numbered folder.
3. For each entry, the script builds the candidate password list from the archive name, inner-entry names, and common passwords, then tries each one (with UTF-8/GBK fallback for non-ASCII passwords).
4. Every extracted file goes back into the queue, so nested archives are unpacked automatically regardless of depth.
5. When the queue is empty, all final non-ZIP files are printed.

## Configuration

At the top of the script:

```python
COMMON_PASSWORDS = ['password', '123456', ...]  # extend with your own candidates
DELETE_AFTER_EXTRACT = False                     # set True only after you trust the results
```

> **Warning:** Enabling `DELETE_AFTER_EXTRACT` permanently removes each archive right after extraction. Keep it disabled until you have verified the output.

## Limitations

- Only the ZIP container format is supported; RAR/7z archives are detected and skipped (use the appropriate tool for those).
- AES-encrypted ZIPs require the optional `pyzipper` dependency; without it the script reports a clear message instead of failing silently.
- Password guessing is dictionary-based (filename variants + common passwords); it does not brute-force arbitrary passwords.

## License

MIT — free to use, modify, and distribute.
