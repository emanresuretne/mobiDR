#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<sys/socket.h>  
#include<netinet/in.h>  

#include <tee_client_api.h>

#include <socket_test_ta.h>

#define MAXLINE 4096  

#define MAX_MESSAGE_LENGTH 4096

#define SECTOR 512
typedef unsigned char *byte_pointer;


int string_cmp(unsigned char *s1, unsigned char *s2)
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

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	
	TEEC_UUID uuid = TA_SOCKET_TEST_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

int main(void)
{
	struct test_ctx ctx;
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	prepare_tee_session(&ctx);

// --------------------------- //
//      Open Connection TCP/IP
// --------------------------- //

	char server_addr[255] = "127.0.0.1";
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 4433;
	op.params[1].tmpref.buffer = server_addr;
	op.params[1].tmpref.size = sizeof(server_addr);

	printf("server %s:%d\n", server_addr, op.params[0].value.a);

	printf("Invoking TA to socket open\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_OPEN_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);


// --------------------------- //
//      Read Data from flash and send to server
// --------------------------- //

	int fd, nr, BUF_SIZE;
	// int fd2, nw;
	unsigned char* buf = NULL;
	unsigned char buf3[2060];

	unsigned char buf2[20];

	static char *back_up="Backup finished";

	BUF_SIZE = 2048;


	/*
	char *str = malloc(BUF_SIZE + 1);
	memset(str, 'b', BUF_SIZE);
	str[BUF_SIZE] = 0;
	memcpy(str, back_up, 12);

	printf("%s\n", str);

	*/

	// DIRECT IO
	printf("Direct IO ---------\n");
	if (posix_memalign((void *)&buf, SECTOR, BUF_SIZE)) {
		perror("posix_memalign failed");
	}
	else {
		if ((fd = open("/home/pi/Desktop/U/backup_start", O_RDONLY | O_DIRECT)) == -1) perror("[open]");
		// if ((fd2 = open("/home/pi/Desktop/flash.back", O_WRONLY | O_CREAT | O_APPEND)) == -1) perror("[open]");

		/* buf size , buf alignment and offset has to observe hardware restrictions */

		/* send initial message to server */
		memcpy(buf3, "restore start", strlen("restore start"));
		hmac_sha1(buf2, buf3, strlen("restore start"));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
		// op.params[0].tmpref.buffer = msg;
		// op.params[0].tmpref.size = strlen(msg);
		op.params[0].tmpref.buffer = buf3;
		op.params[0].tmpref.size = 2060;
		op.params[2].tmpref.buffer = buf2;
		op.params[2].tmpref.size = 20;

		printf("Invoking TA to socket send\n");
		res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_SEND_CMD, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		printf("%d Bytes sent\n\n", op.params[1].value.a);
		printf("Vefify result is %d\n\n", op.params[1].value.a);

		/* read data from flash */
		
		if((nr = read(fd, buf, BUF_SIZE)) == -1) {perror("[pread]");}
		while(strcmp(buf, back_up) != 0)
		{
			memcpy(buf3, buf, BUF_SIZE);
			lseek(fd,0,SEEK_SET);
			if((nr = read(fd, buf, BUF_SIZE)) == -1) {
				perror("[pread]");
			}
			else {
				memcpy(buf3+BUF_SIZE, buf, 12);
				memcpy(buf2, buf+12, 20);
				// printf("%i bytes read %.2x %.2x ...\n",nr,buf[0],buf[1]);
				printf("page read: %s\n", buf);
				show_bytes(buf, BUF_SIZE);
				if (strcmp(buf, back_up) != 0) {
					memset(&op, 0, sizeof(op));
					op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
					// op.params[0].tmpref.buffer = msg;
					// op.params[0].tmpref.size = strlen(msg);
					op.params[0].tmpref.buffer = buf3;
					op.params[0].tmpref.size = 2060;
					op.params[2].tmpref.buffer = buf2;
					op.params[2].tmpref.size = 20;

					printf("Invoking TA to socket send\n");
					res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_SEND_CMD, &op, &err_origin);
					if (res != TEEC_SUCCESS)
						errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
							res, err_origin);

					printf("%d Bytes sent\n\n", op.params[1].value.a);
					printf("Vefiry result is %d\n\n", op.params[1].value.a);

					// if((nw = write(fd2, buf, BUF_SIZE)) == -1) perror("[pwrite]");
				}
			}
			lseek(fd,0,SEEK_SET);
			if((nr = read(fd, buf, BUF_SIZE)) == -1) {
				perror("[pread]");
			}
		}

		/* send end message to server */
		memcpy(buf3, "restore stop", strlen("restore stop"));
		hmac_sha1(buf2, buf3, strlen("restore stop"));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
		// op.params[0].tmpref.buffer = msg;
		// op.params[0].tmpref.size = strlen(msg);
		op.params[0].tmpref.buffer = buf3;
		op.params[0].tmpref.size = 2060;
		op.params[2].tmpref.buffer = buf2;
		op.params[2].tmpref.size = 20;

		printf("Invoking TA to socket send\n");
		res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_SEND_CMD, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		printf("%d Bytes sent\n\n", op.params[1].value.a);
		printf("Vefiry result is %d\n\n", op.params[1].value.a);
		
		free(buf);
		// free(buf2);
		// free(buf3);

		if(close(fd) == -1) perror("[close]");
		// if(close(fd2) == -1) perror("[close]");
	}



// --------------------------- //
//      Send Message to server
// --------------------------- //

/*

	char msg[] = "Hello World";
	printf("message (%d bytes): %s\n", strlen(msg), msg);

	unsigned char buf[2048];
	unsigned char buf2[20] = {0x82, 0x9d, 0xb1, 0x4e, 0x11, 0xdb, 0x82, 0x12, 0x25, 0x6c, 0x74, 0x6f, 0xc8, 0x2d, 0x76, 0xcf, 0xcf, 0x89, 0xe3, 0x72};
	int BUF_SIZE = 2048;

	memset(buf, 'a', BUF_SIZE);
	// memset(buf2, 'b', 20);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	// op.params[0].tmpref.buffer = msg;
	// op.params[0].tmpref.size = strlen(msg);
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = 2048;
	op.params[2].tmpref.buffer = buf2;
	op.params[2].tmpref.size = 20;

	printf("Invoking TA to socket send\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_SEND_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("%d Bytes sent\n\n", op.params[1].value.a);
	printf("Return value is %d\n\n", op.params[1].value.a);

*/

// --------------------------- //
//      Recv Message
// --------------------------- //

	unsigned char msg_received[100];
	unsigned char digest[20];
    unsigned char recdigest[20];
	unsigned char signbuf[28];

	memset(msg_received, 0x0, sizeof(msg_received));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = msg_received;
	op.params[0].tmpref.size = sizeof(msg_received);

	printf("Invoking TA to socket recv\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_RECV_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("message received (%d bytes): %s\n\n", op.params[0].tmpref.size, msg_received);

	memcpy(signbuf, msg_received, 8);
    memcpy(recdigest, msg_received+8, 20);
    hmac_sha1(digest, signbuf, 2060);
    if (!string_cmp(digest, recdigest)) {
        printf("hmac match \n");
		printf("verify result is :\n");
		show_bytes(signbuf, 8);
    }

// --------------------------- //
//      Close connection
// --------------------------- //

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	printf("Invoking TA to socket close\n");
	res = TEEC_InvokeCommand(&ctx.sess, TA_SOCKET_CLOSE_CMD, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("Connection closed\n");

// ------------------------------ //

	TEEC_CloseSession(&ctx.sess);

	TEEC_FinalizeContext(&ctx.ctx);

	return 0;
}
