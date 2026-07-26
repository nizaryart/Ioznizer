# Samples

Live malware is **not** distributed in this repository. Publishing an executable
DDoS bot to a public repository trips endpoint protection on every clone, and
distributing unencrypted malware breaches GitHub's Acceptable Use Policies.

## Benign control sample

`time` is a harmless local utility (reads a file, shuffles the bytes, prints
them). It is committed so the pipeline can be exercised end to end, and it acts
as the negative control: a correct run must classify it as benign with an empty
`malicious_behaviors` array.

```bash
./run.sh samples/time
```

## Malicious sample used in the documented results

The DDoS flooder referenced in the README is identified by hash only:

```
SHA-256  7fe9b559e58af2bc4b453a5bcdbdfef0b2d527bdc3416ee801613ac1734baa03
Type     ELF 32-bit LSB executable, Intel i386, statically linked, stripped
Family   DDoS bot / network flooder (UDP, TCP SYN, ICMP, ACK floods)
```

Source it yourself from a malware repository such as MalwareBazaar or VirusTotal,
then place it in this directory.

## Handling

- Never execute a sample. This project performs static analysis only; nothing in
  the pipeline runs the binary.
- Keep samples non-executable: `chmod -x samples/*`
- Analyse in an isolated VM. Decompilation runs under `bwrap` with networking
  disabled where available (see `backend/decompiler.py`).
- If you add samples of your own, `.gitignore` already excludes `*.elf` and
  `*.bin` so they are not committed by accident.
