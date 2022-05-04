# Solution

We are given a image file. Lets see if we can find out  something.

# Binwalk

```binwalk``` is used to find out if there are some files hidden inside our image file or not.
```
binwalk park.jpg
```

Output:
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
382           0x17E           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"

```

Nothing new found.

# Strings

```strings``` command is used to capture all ASCII strings from the image file.
```
strings park.jpg
```

Output:
```
wae:uc(>YwG
6	`A
xhS~
wM=GV
gDau%~
,~J|
u)(])F
={~5
h--@3
cZi-
M(.I
]hWP&
jc#k
=7g&
mjx/
s\]|."Ue
\qZf
Here is a flag "devCLUB{more_than_m33ts_the_3y3b7FBD20b}"
```

and yeah we found the flag.
