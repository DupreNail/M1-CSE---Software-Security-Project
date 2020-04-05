#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "headers.h"

char *getFunctionAddr(FILE *fp, char *buffer, char *command, char**argv, char *functionAddr) {
  sprintf(command, "nm %s", argv[1]);
  fp = popen(command, "r");
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }
  while	(fgets(buffer, MALLOC_SIZE, fp) != NULL) {
    if (strstr(buffer, argv[2]) != NULL) {
      functionAddr = strtok(buffer, " ");
      break;
    }
  }
  pclose (fp);
  return (functionAddr);
}

char *getPID(FILE *fp, char *buffer, char *command, char **argv) {
  sprintf(command, "pgrep %s", argv[1]);
  fp = popen(command, "r");
  free(command);
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }

  fgets(buffer, MALLOC_SIZE, fp);
  pclose(fp);
  return (buffer);
}

long long getAddrFunc(char *pid, char *command, FILE *fp, char *buffer, char *functionAddr) {
  pid[strlen(pid) - 1] = pid[strlen(pid)];
  sprintf(command,"cat /proc/%s/maps", pid);
  fp = popen(command, "r");
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }

  long long addr;

  if( fgets(buffer, MALLOC_SIZE, fp) != NULL) {
    char *tokResult = strtok(buffer, " ");
    char * firstAddr = strtok(tokResult, "-");
    addr = strtoul(firstAddr, NULL, 16);
    addr += strtoul(functionAddr,NULL, 16);
  }
  pclose(fp);
  return(addr);
}

long long step1(char **argv) {
  
  FILE *fp;
  char *buffer;
  char *command;
  char *functionAddr;
  char *pid;
  long long traceeFuncAddr;


  buffer = malloc(sizeof(char) * MALLOC_SIZE);
  command = malloc(sizeof(char) * (strlen(argv[1]) + strlen("nm ") + 1));
  functionAddr = getFunctionAddr(fp, buffer, command, argv, functionAddr);
  char *temp = malloc(sizeof(char) * strlen(functionAddr) + 1);
  strcpy(temp, functionAddr);
  free(command);
 
  command = malloc(sizeof(char) * (strlen(argv[1]) + strlen("pgrep ") + 1));
  buffer = getPID(fp, buffer, command, argv);
  pid = strdup(buffer);
  command = malloc(sizeof(char) * (strlen("cat /proc//maps") + strlen(pid) + 1));

  traceeFuncAddr = getAddrFunc(pid, command, fp, buffer, temp);
  free(command);
  free(pid);
  free(functionAddr);
  free(temp);
  printf("%llx", traceeFuncAddr); 
  return (traceeFuncAddr);

}
