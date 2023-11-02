# ANSI ESCAPE SEQUENCES

> Weaponizing Plain Text ANSI Escape Sequences as a Forensic Nightmare - STÖK
> https://www.youtube.com/watch?v=3T2Al3jdY38

## Cleaning ANSI Escape Sequence
### Using `sed`:

You can use the `sed` utility to remove ANSI escape sequences from a file.

```bash
sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' input.txt > output.txt
```

Here, `input.txt` is the file with the ANSI codes, and `output.txt` is the cleaned file.

### Using `awk`:

You can use `awk` as well to achieve the same:

```bash
awk '{gsub(/\x1b\[[0-9;]*[a-zA-Z]/, "")}1' input.txt > output.txt
```

### Using `perl`:

Perl offers similar text processing capabilities:

```bash
perl -pe 's/\x1b\[[0-9;]*[mK]//g' input.txt > output.txt
```

### Using Python:

You can also write a Python script to do the same. Save the following code to a file, say `clean_ansi.py`, and run it.

```python
import re

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

if __name__ == '__main__':
    with open('input.txt', 'r') as infile:
        text = infile.read()
        
    cleaned_text = remove_ansi_escape_sequences(text)
    
    with open('output.txt', 'w') as outfile:
        outfile.write(cleaned_text)
```

Run it like so:

```bash
python clean_ansi.py
```

Each of these methods reads from `input.txt` and writes the cleaned text to `output.txt`. Adjust the filenames as needed.
