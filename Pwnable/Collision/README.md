# Collision
Let's jump into the challenge.

## SSH

Lets ssh into the challenge and see what all files are there.

```
ssh col@pwnable.kr -p2222 (pw:guest)
```

After ssh'ing into the vm we can list the resources and permissions we have to work with.

```
col@pwnable:~$ ls -al
total 36
drwxr-x---   5 root    col     4096 Oct 23  2016 .
drwxr-xr-x 116 root    root    4096 Nov 11 14:52 ..
d---------   2 root    root    4096 Jun 12  2014 .bash_history
-r-sr-x---   1 col_pwn col     7341 Jun 11  2014 col
-rw-r--r--   1 root    root     555 Jun 12  2014 col.c
-r--r-----   1 col_pwn col_pwn   52 Jun 11  2014 flag
dr-xr-xr-x   2 root    root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root    root    4096 Oct 23  2016 .pwntools-cache
```

Run ```whoami``` to see who you are currently logged in as

```bash
col@pwnable:~$ whoami
col
```
So we can read and execute col.c and col files repectively and we dont have permission to read flag file.

Lets take a look at col.c

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

* First it checks and verifies using the argument counter that the argument vector contains more than 2 elements. Means it checks if we have given one argument while running the program.
* Then it checks and verifies using the length of the password that the password is 20 bytes.
* Then it checks and verifies using the hashcode that the password is correct.
* ```check_password``` takes the password as an argument and returns the sum of the first 5 integers.
* We know that an int is 4 bytes, while a char is 1 byte. Lets try to just split it into 5 evenly sized chunks.
* Divided ```0x21DD09EC``` by 5 gives us 4 as remainder. So let our four integers be ```06C5CEC8``` and the last integer be(+4) ```06C5CECC```.
* Now we need to check whether our system is big endian or little endian, so that we can give input in the following manner.

## Endianess

Run the following command to check the endianess of the system.

```bash
col@pwnable:~$ python -c "import sys;print(0 if sys.byteorder=='big' else 1)"
Output : 1
```
Right, so we are on a little endian system. So we need to reverse the input.

## Results

We need to input ```06C5CEC8``` four times and ```06C5CECC``` once.

```bash
./col `python -c 'print("\xC8\xCE\xC5\x06"*4 + "\xCC\xCE\xC5\x06")'`

daddy! I just managed to create a hash collision :)
```

and yipee got the flag.
