# File Descriptor

For this challenge, you should have a basic understanding of the ```file descriptor``` in Linux. So what is file descriptor? 

A ```file descriptor``` is a number that uniquely identifies an open file in a computer's operating system. It describes a data resource, and how that resource may be accessed. When a program asks to open a file — or another data resource, like a network socket — the kernel: Grants access.

* ```Read from stdin``` => read from fd 0 : Whenever we write any character from keyboard, it read from stdin through fd 0 and save to file named /dev/tty.
* ```Write to stdout``` => write to fd 1 : Whenever we see any output to the video screen, it’s from the file named /dev/tty and written to stdout in screen through fd 1.
* ```Write to stderr``` => write to fd 2 : We see any error to the video screen, it is also from that file write to stderr in screen through fd 2.


Let's jump into the challenge.

## SSH

Lets ssh into the challenge and see what all files are there.

```
ssh fd@pwnable.kr -p2222 (pw:guest)
```

After ssh'ing into the vm we can list the resources and permissions we have to work with.

```
fd@pwnable:~$ ls -al
total 40
drwxr-x---   5 root   fd   4096 Oct 26  2016 .
drwxr-xr-x 116 root   root 4096 Nov 11 14:52 ..
d---------   2 root   root 4096 Jun 12  2014 .bash_history
-r-sr-x---   1 fd_pwn fd   7322 Jun 11  2014 fd
-rw-r--r--   1 root   root  418 Jun 11  2014 fd.c
-r--r-----   1 fd_pwn root   50 Jun 11  2014 flag
-rw-------   1 root   root  128 Oct 26  2016 .gdb_history
dr-xr-xr-x   2 root   root 4096 Dec 19  2016 .irssi
drwxr-xr-x   2 root   root 4096 Oct 23  2016 .pwntools-cache
```

Run ```whoami``` to see who you are currently logged in as

```bash
fd@pwnable:~$ whoami
fd
```
So we can read and execute fd.c and fd files repectively and we dont have permission to read flag file.

Lets take a look at fd.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

* First it checks and verifies using the argument counter that the argument vector contains more than 2 elements. Means it checks if we have given one argument while running the program.

* Further, the program uses atoi() which turns our input into an int, subtracts 0x1234 from it, and stores it in our fd variable.

```read``` -> From the file indicated by the file descriptor fd, the ```read()``` function reads cnt bytes of input into the memory area indicated by buf.

```c
size_t read (int fd, void* buf, size_t cnt); 
```

* It then takes the above calculated file descriptor to read into ```buf```. To give input from stdin, we need fd to be 0 and then give input as ```LETMEWIN\n```.

Lets try it out.

## Output

```bash
fd@pwnable:~$ ./fd 4660
LETMEWIN
```

Flag
```
good job :)
mommy! I think I know what a file descriptor is!!
```
