#include <windows.h>
#if defined(__GNUC__)
 #include <winsock2.h>
#endif
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/*
	cl /c vuln_bof.c
	link /out:vuln_bof.exe vuln_bof.obj /nxcompat:no /fixed

	cl /c vuln_bof.c
	link vuln_bof.obj /out:vuln_bof.dll /dll /nxcompat:no /fixed
*/

#define BUF_SIZE 4
#define SHELLCODE_SIZE 1024*200
#define MAX_CON 1
#define RECON_INTERVAL_MS 5000
#define IP "10.0.0.1"
#define PORT "8888"

char *buf;
unsigned int buf_size;
unsigned int i;

void die(char * mes)
{
	//printf( "%s: %d\n", mes, WSAGetLastError() );
	ExitProcess(-1);
}

//0x00401570 + 3 # radare2 -q -c 'isq~for_rop1' b.exe
void for_rop1(void)
{
	#if defined(__GNUC__) || defined(__MINGW32__)
	 asm("mov %esp, 8(%esp); ret");
	#elif defined(_MSC_VER)
	 __asm {
		mov [esp+8], esp
		ret
	 }
	#endif
}

//0x0040157b # radare2 -q -c 'isq~for_rop2' b.exe
void for_rop2(LPVOID addr)
{
	//VirtualAlloc(addr, 0x1, 0x1000, 0x40);
	VirtualAlloc(addr, SHELLCODE_SIZE, 0x1000, 0x40);
}

//0x004015ac + 3 # radare2 -q -c 'isq~for_rop3' b.exe
void for_rop3(void)
{
	#if defined(__GNUC__) || defined(__MINGW32__)
	 asm("add $4, %esp; push %esp; ret");
	#elif defined(_MSC_VER)
	 __asm {
		add esp, 4
		push esp
		ret
	 }
	#endif
}

void parse()
{
	char vuln_buf[BUF_SIZE];
	for(i = 0; i < buf_size; i++)
	{
		vuln_buf[i] = buf[i] ^ 0x41;
		i++;
		vuln_buf[i] = buf[i] ^ 0x4f;
	}
}

void do_bind(char **argv)
{
	char stack_space[SHELLCODE_SIZE];
	WSADATA wsa_data;
	SOCKET s,c;
	struct sockaddr_in sock_addr;
	int recv_bytes = 0;

	if( WSAStartup( MAKEWORD(2, 2), &wsa_data ) )
		die("WSAStartup() error");

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	sock_addr.sin_port = htons( atoi( argv[1] ) );

	s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
	if( s == INVALID_SOCKET )
		die("socket() error");

	if( bind( s, (struct sockaddr *) &sock_addr, sizeof(sock_addr) ) )
		die("bind() error");

	if( listen(s, MAX_CON) )
		die("listen() error");

	while(1)
	{
		c = accept(s, 0, 0);
		if(c == INVALID_SOCKET)
			die("accept() error");
		printf("incoming connect\n");
		buf = stack_space;
		buf_size = 0;
		do
		{
			recv_bytes = recv(c, stack_space + buf_size, SHELLCODE_SIZE - buf_size, 0);
			buf_size += recv_bytes;
			//send(c, "ok", 2, 0);
			printf("received %d bytes\n", recv_bytes);
		} while(recv_bytes);
		parse();
		closesocket(c);
	}

	closesocket(s);
	WSACleanup();
}

void do_connect(char **argv)
{
	char stack_space[SHELLCODE_SIZE];
	WSADATA wsa_data;
	SOCKET c;
	struct sockaddr_in sock_addr;
	int recv_bytes;

	if( WSAStartup( MAKEWORD(2, 2), &wsa_data ) )
		die("WSAStartup() error");

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = inet_addr( argv[1] );
	sock_addr.sin_port = htons( atoi( argv[2] ) );

	while(1)
	{
		c = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
		if( c == INVALID_SOCKET )
			die("socket() error");
		if( connect( c, (struct sockaddr *) &sock_addr, sizeof(sock_addr) ) )
			printf("connect() error\n");
		else
		{
			printf("connected\n");
			buf = stack_space;
			buf_size = 0;
			do
			{
				recv_bytes = recv(c, stack_space + buf_size, SHELLCODE_SIZE - buf_size, 0);
				buf_size += recv_bytes;
				//send(c, "ok", 2, 0);
				printf("received %d bytes\n", recv_bytes);
			} while(recv_bytes);
			parse();
		}
		Sleep(RECON_INTERVAL_MS);
	}
	
	closesocket(c);
	WSACleanup();
}

/*
int is_started = 0;
char *args1[] = {"b.exe", IP, PORT};
char *args2[] = {"b.exe", PORT};
int DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	HANDLE threads[2];
	int threads_id[2];

	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			if(!is_started)
			{
				threads[0] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)do_connect, args1, 0, &threads_id[0]);
				threads[1] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)do_bind, args2, 0, &threads_id[1]);
				is_started = 1;
			}
			break;
	}
	return 1;
}
*/

void main(int argc, char ** argv)
{
	HANDLE threads[2];
	int threads_id[2];

	threads[0] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)do_connect, (char *[]){"b.exe", IP, PORT}, 0, &threads_id[0]);
	threads[1] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)do_bind, (char *[]){"b.exe", PORT}, 0, &threads_id[1]);
	WaitForMultipleObjects(2, threads, TRUE, INFINITE);
}