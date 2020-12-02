#include <string.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];


static uint8_t m_response_message_buffer[200];


u32 get_time_seconds(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}



void randombytes(unsigned char *ptr, unsigned long long length)
{
  int i ; 
  printf("\n\nrandombytes called!!!\n\n");
  //int i;
  u32 t = get_time_seconds();

  for(i = 0; i < length; i++){
      ptr[i] = t >> (i*8);
  }
}


void printMessage(uint8_t *msg, int size){
    int i = 0; 
    printf("0x");
    for(;i<size; i++){
        printf("%02x", msg[i]);
    }
    printf("\n");
}








07003A270A2E453443C3790E657CEBE634B03F0102F45681B40671D46E6E15EDF0200000083B33643C6D97EF77ED51C02A277CBF7EA479915982F13C61D997A56678AD77791BFA7E95229A3DD34F87132BF3E3C97DB9F2


















int main(){

  int size = 32;
  unsigned char *ptr = malloc(sizeof(unsigned char)*32); 

  randombytes(ptr, size);

    for (int i = 0; i < size; i++) {
      printf("%x", ptr[i]);
    }


    printf("()\n" );
  //REMOVE LATER
  printf("M_RESPONSE_MESSAGE_BUFFER: ");
  printMessage(m_response_message_buffer, 36);
  
  uint8_t response_emu[] = "\xFF\xFF\xFF\xFF";
  
  memcpy(m_response_message_buffer, response_emu, sizeof(uint8_t)*36);

  printf("M_RESPONSE_MESSAGE_BUFFER: ");
  printMessage(m_response_message_buffer, 36);
  //REMOVE LATER

}
