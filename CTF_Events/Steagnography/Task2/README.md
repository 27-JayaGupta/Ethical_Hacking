# Solution

```Daunt``` is a executable file given to us. Lets see if we can find out something useful.

# GDB
    
```gdb``` is used to debug the program.

```
gdb Daunt

Output:

not in executable format: file format not recognized
```

# File

```file``` command is used to get basic informantion about the file.

```
file Daunt
```

Output:

```
Daunt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), corrupted program header size, missing section headers
```

```Missing section headers```, hmm interesting, this means that the header of the executable is corrupted. Lets check its header info.

# Readelf

```readelf``` displays information about one or more ELF format object files. The options control what particular information to display. 

```
readelf -a Daunt
```

Output:

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4004bdbfef
  Start of program headers:          4194304 (bytes into file)
  Start of section headers:          -4773833481741467648 (bytes into file)
  Flags:                             0xb
  Size of this header:               0 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         56
  Section header string table index: 9
readelf: Error: Reading 3584 bytes extends past end of file for section headers
readelf: Error: Section headers are not available!
readelf: Warning: possibly corrupt ELF header - it has a non-zero program header offset, but no program headers
```

According to my reseacrh, most probably the ```Number of Section headers``` is wrong.

# Recovery of Corrupted Header

Used the following python file to get back the corrupted header.

```script.py```
```
#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
from struct import pack

with open('Daunt', 'rb+') as f:
    elffile = ELFFile(f)
    e_shnum = len(elffile.get_section(28).data().decode('ascii').split('\x00')) + 1 
    f.seek(48)
    f.write(pack('h', e_shnum))
```

and then execute it.

```
python3 script.py
```

but no output :(
    <br/>
Lets go one step backward and try to read the strings from the executable.

# Strings

```strings``` is used to find the Ascii Characters in the any type of file.

```
strings Daunt | grep "{"
```

Output:
```
DEV{HuRRY_up_247862451}
```

Yipee, got the flag.