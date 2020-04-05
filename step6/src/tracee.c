#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
int test = 0;

void f1(){
  test += 1;
  printf("PRINT! %d\n", test);
  return;
}

int f2(int i){
  printf("PAGESIZE:%d\n",getpagesize());
  //i += 100;
  printf("In F2, value of parameter is %d", i);
  return (i);
}

int main(void) {
  
  void  *f1_ptr; //declaration of pointer to the function
  f1_ptr = &f1;


  

  printf("@MPRTOECT: %p \n", (void*)mprotect);
  printf(" Address of function = [%p]",  f1_ptr);
  fflush(0);
   while (1) {
    f1();
    sleep(1);
    }

  
    FILE *fp;

    int pid  = getpid();
char * command = malloc(sizeof(char) * (strlen("cat /proc//maps") + 5 + 1));
  printf("COMMAND:%s\n\n", command);

  char *tempBuff;
  sprintf(command, "cat /proc/%d/maps",pid);

  char *buffer = malloc(sizeof(char) * 128);
 
  fp = popen(command, "r");
  if (fp == NULL) {
    exit(-1
	 );
  }
  while (fgets(buffer, 128, fp) != NULL) {
     if ((strstr(buffer, "heap") != NULL) && (strstr(buffer, "rw-p") != NULL)) {
      tempBuff = strtok(buffer, "-");
      printf("\nTracee: %s\n",tempBuff);
       break;
    }
  }
  void *pointer = (void*)strtol(tempBuff,NULL, 16);
  posix_memalign(pointer,32,4096);

  printf("MPROTECT ARGUMENTS: %p||%d||%d\n", pointer, getpagesize(), PROT_WRITE);
  printf("RESULT:%d", mprotect(pointer,getpagesize(), PROT_WRITE));



	 
  return (1);
}
