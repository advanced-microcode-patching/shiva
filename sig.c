#include  <stdio.h>
#include  <signal.h>
#include  <setjmp.h>

jmp_buf  JumpBuffer;

void     INThandler(int);

void  main(void)
{
     signal(SIGINT, INThandler);

     while (1) {
          if (setjmp(JumpBuffer) == 0) {
             printf("Hit Ctrl-C at anytime ... \n");
                  pause();
          }
     }
}

void  INThandler(int  sig)
{
     char  c;

 //    signal(sig, SIG_IGN);
     printf("OUCH, did you hit Ctrl-C?\n"
            "Do you really want to quit? [y/n] ");
     c = getchar();
     if (c == 'y' || c == 'Y')
          exit(0);
     else {
     //     signal(SIGINT, INThandler);
          longjmp(JumpBuffer, 1);
     }
}
