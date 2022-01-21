#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<sys/socket.h>  
#include<netinet/in.h>  
#include<errno.h> 
#include <arpa/inet.h>


#define MAXLINE 4096  

#define MAX_MESSAGE_LENGTH 4096


#define SECTOR 512

typedef unsigned char *byte_pointer;

int string_cmp(unsigned char *s2, unsigned char *s1)
{
  int i;
  for (i = 0; s1[i] == s2[i]; i++)
    if (s1[i] == '\0')
      return 0;
  return s1[i] - s2[i];
}

// extern void hmac_sha1(unsigned char *digest, unsigned char *data, int data_length);

int
sha1digest(uint8_t *digest, const uint8_t *data, size_t databytes)
{
#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

  uint32_t W[80];
  uint32_t H[] = {0x67452301,
                  0xEFCDAB89,
                  0x98BADCFE,
                  0x10325476,
                  0xC3D2E1F0};
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f = 0;
  uint32_t k = 0;

  uint32_t idx;
  uint32_t lidx;
  uint32_t widx;
  uint32_t didx = 0;

  int32_t wcount;
  uint32_t temp;
  uint64_t databits = ((uint64_t)databytes) * 8;
  uint32_t loopcount = (databytes + 8) / 64 + 1;
  uint32_t tailbytes = 64 * loopcount - databytes;
  uint8_t datatail[128] = {0};

  if (!digest)
    return -1;

  if (!data)
    return -1;

  /* Pre-processing of data tail (includes padding to fill out 512-bit chunk):
     Add bit '1' to end of message (big-endian)
     Add 64-bit message length in bits at very end (big-endian) */
  datatail[0] = 0x80;
  datatail[tailbytes - 8] = (uint8_t) (databits >> 56 & 0xFF);
  datatail[tailbytes - 7] = (uint8_t) (databits >> 48 & 0xFF);
  datatail[tailbytes - 6] = (uint8_t) (databits >> 40 & 0xFF);
  datatail[tailbytes - 5] = (uint8_t) (databits >> 32 & 0xFF);
  datatail[tailbytes - 4] = (uint8_t) (databits >> 24 & 0xFF);
  datatail[tailbytes - 3] = (uint8_t) (databits >> 16 & 0xFF);
  datatail[tailbytes - 2] = (uint8_t) (databits >> 8 & 0xFF);
  datatail[tailbytes - 1] = (uint8_t) (databits >> 0 & 0xFF);

  /* Process each 512-bit chunk */
  for (lidx = 0; lidx < loopcount; lidx++)
  {
    /* Compute all elements in W */
    memset (W, 0, 80 * sizeof (uint32_t));

    /* Break 512-bit chunk into sixteen 32-bit, big endian words */
    for (widx = 0; widx <= 15; widx++)
    {
      wcount = 24;

      /* Copy byte-per byte from specified buffer */
      while (didx < databytes && wcount >= 0)
      {
        W[widx] += (((uint32_t)data[didx]) << wcount);
        didx++;
        wcount -= 8;
      }
      /* Fill out W with padding as needed */
      while (wcount >= 0)
      {
        W[widx] += (((uint32_t)datatail[didx - databytes]) << wcount);
        didx++;
        wcount -= 8;
      }
    }

    /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential optimization from:
       "Improving the Performance of the Secure Hash Algorithm (SHA-1)" by Max Locktyukhin */
    for (widx = 16; widx <= 31; widx++)
    {
      W[widx] = SHA1ROTATELEFT ((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
    }
    for (widx = 32; widx <= 79; widx++)
    {
      W[widx] = SHA1ROTATELEFT ((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
    }

    /* Main loop */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    for (idx = 0; idx <= 79; idx++)
    {
      if (idx <= 19)
      {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      }
      else if (idx >= 20 && idx <= 39)
      {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      }
      else if (idx >= 40 && idx <= 59)
      {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      }
      else if (idx >= 60 && idx <= 79)
      {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      temp = SHA1ROTATELEFT (a, 5) + f + e + k + W[idx];
      e = d;
      d = c;
      c = SHA1ROTATELEFT (b, 30);
      b = a;
      a = temp;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
  }

  /* Store binary digest in supplied buffer */
  if (digest)
  {
    for (idx = 0; idx < 5; idx++)
    {
      digest[idx * 4 + 0] = (uint8_t) (H[idx] >> 24);
      digest[idx * 4 + 1] = (uint8_t) (H[idx] >> 16);
      digest[idx * 4 + 2] = (uint8_t) (H[idx] >> 8);
      digest[idx * 4 + 3] = (uint8_t) (H[idx]);
    }
  }

  return 0;
}  /* End of sha1digest() */

void hmac_sha1(
                unsigned char *digest,
                unsigned char *data,
                int data_length
                )

{
    int b = 64; /* blocksize */
    unsigned char ipad = 0x36;

    unsigned char opad = 0x5c;

    unsigned char k0[64];
    unsigned char k0xorIpad[64];
    unsigned char step7data[64];
    unsigned char step5data[MAX_MESSAGE_LENGTH+128];
    unsigned char step8data[64+20];
    int i;
    
    unsigned char key[64] = {0x6a, 0x49, 0x4d, 0x4f, 0x43, 0x37, 0x44, 0x36, 0x58, 0x63, 0x59, 0x44, 0x4f, 0x45, 0x32, 0x71, 0x53, 0x5a, 0x4b, 0x73, 0x73, 0x31, 0x61, 0x63, 0x4d, 0x5a, 0x54, 0x53, 0x43, 0x6e, 0x62, 0x4e, 0x44, 0x56, 0x53, 0x61, 0x75, 0x77, 0x39, 0x53, 0x63, 0x63, 0x72, 0x61, 0x39, 0x69, 0x43, 0x49, 0x33, 0x33, 0x35, 0x42, 0x51, 0x76, 0x77, 0x66, 0x45, 0x35, 0x6e, 0x56, 0x6d, 0x6e, 0x4c, 0x56};
    int key_length = 64;
    
    /*
    for(int i0=0;i0<32;i0++)
    {
      unsigned char temp=key[i0];
      key[i0]=key[63-i0];
      key[63-i0]=temp;
    }
    */

    for (i=0; i<64; i++)
    {
        k0[i] = 0x00;
    }



    if (key_length != b)    /* Step 1 */
    {
        /* Step 2 */
        if (key_length > b)      
        {
            sha1digest(digest, key, key_length);
            for (i=0;i<20;i++)
            {
                k0[i]=digest[i];
            }
        }
        else if (key_length < b)  /* Step 3 */
        {
            for (i=0; i<key_length; i++)
            {
                k0[i] = key[i];
            }
        }
    }
    else
    {
        for (i=0;i<b;i++)
        {
            k0[i] = key[i];
        }
    }
    /* Step 4 */
    for (i=0; i<64; i++)
    {
        k0xorIpad[i] = k0[i] ^ ipad;
    }
    /* Step 5 */
    for (i=0; i<64; i++)
    {
        step5data[i] = k0xorIpad[i];
    }
    for (i=0;i<data_length;i++)
    {
        step5data[i+64] = data[i];
    }

    /* Step 6 */
    sha1digest(digest, step5data, data_length+b);

    /* Step 7 */
    for (i=0; i<64; i++)
    {
        step7data[i] = k0[i] ^ opad;
    }

    /* Step 8 */
    for (i=0;i<64;i++)
    {
        step8data[i] = step7data[i];
    }
    for (i=0;i<20;i++)
    {
        step8data[i+64] = digest[i];
    }

    /* Step 9 */
    sha1digest(digest, step8data, b+20);
}

void show_bytes(byte_pointer start, int len) {
    int i;
    for (i = 0; i < len; i++)
    printf(" %.2x", start[i]);    //line:data:show_bytes_printf
    printf("\n");
}



int main(){

int fd, fd2, nr, nw, BUF_SIZE;
//char fl_nm[]={"/home/wen/Desktop/U/backup_start"};
unsigned char* buf = NULL;

static char *back_up="Backup finished";
static char *backup_start="backup_start";

BUF_SIZE = 2048;

unsigned char buf3[2060];

unsigned char buf2[20];
unsigned char digest2[20];

unsigned char sendbuff[2080];
unsigned char writebuff[2048];

const char *tmp1 = "restore start";
const char *tmp2 = "backup stop";


/*
char *str = malloc(BUF_SIZE + 1);
memset(str, 'b', BUF_SIZE);
str[BUF_SIZE] = 0;
memcpy(str, back_up, 12);

printf("%s\n", str);

*/


// --------------------------- //
//      Open Connection TCP/IP
// --------------------------- //

int sockfd, n,rec_len;  
char recvline[4096], sendline[4096];  
// char buf[MAXLINE];  
struct sockaddr_in servaddr;  
  
if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){  
    printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);  
    exit(0);  
}  
  
memset(&servaddr, 0, sizeof(servaddr));  
servaddr.sin_family = AF_INET;  
servaddr.sin_port = htons(4433);  
if( inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr) <= 0){ 
    printf("inet_pton error for %s\n","127.0.0.1");  
    exit(0);  
}  
   
if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){  
    printf("connect error: %s(errno: %d)\n",strerror(errno),errno);  
    exit(0);  
}  

memset(buf3, 0, 2060);
strncpy(buf3, tmp1, 2059);
// memcpy(buf3, "backup start", strlen("backup start"));
hmac_sha1(buf2, buf3, 2060);
memcpy(sendbuff, buf3, 2060); 
memcpy(sendbuff+2060, buf2, 20);

if( send(sockfd, sendbuff, sizeof(sendbuff), 0) < 0)  {  
    printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);  
    exit(0);  
}

    // DIRECT IO
printf("Direct IO ---------\n");
if (posix_memalign((void *)&buf, SECTOR, BUF_SIZE)) {
    perror("posix_memalign failed");
}
else {

    if ((fd2 = open("/home/wen/Desktop/U/backup_initial", O_WRONLY | O_DIRECT | O_TRUNC)) == -1) perror("[open]");

    if((nr = write(fd2, "restore_initial", strlen("restore_initial"))) == -1) perror("[pwrite1]");
    else
        // printf("%i bytes read %.2x %.2x ...\n",nr,buf[0],buf[1]);
        printf("Initial restore: \n");


    if ((fd = open("/home/wen/Desktop/U/backup_start", O_WRONLY | O_DIRECT)) == -1) perror("[open]");
    // if ((fd = open("/home/wen/Desktop/flash.test", O_WRONLY | O_CREAT | O_DIRECT)) == -1) perror("[open]");


    /* buf size , buf alignment and offset has to observe hardware restrictions */

    do
    {
       nr = recv(sockfd, buf3, 2060,0);
       if (nr>0)
       {
           memcpy(writebuff, buf3+BUF_SIZE, 12);
           memcpy(buf, buf3+BUF_SIZE, 12);
           if((nw = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite2]");
           lseek(fd,0,SEEK_SET);
           memcpy(buf, buf3, BUF_SIZE);
           if((nw = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite3]");
           lseek(fd,0,SEEK_SET);
           memset(buf, 0, BUF_SIZE);
       }       
    } while (nr>0);
    

    free(buf);
    // free(buf2);



    if(close(fd) == -1) perror("[close]");
    if(close(fd2) == -1) perror("[close]");
    close(sockfd);  
}

return  0;
}
