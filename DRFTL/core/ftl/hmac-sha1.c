/******************************************************/
/* hmac-sha1()                                        */
/* Performs the hmac-sha1 keyed secure hash algorithm */
/******************************************************/
#include <stdint.h>
#include <stdlib.h>

#define MAX_MESSAGE_LENGTH 4096

extern int sha1digest(uint8_t *digest, const uint8_t *data, size_t databytes);

#ifdef HMAC_DEBUG
debug_out(
            unsigned char *label,
            unsigned char *data,
            int data_length
        )
{
int i,j;
int num_blocks;
int block_remainder;
    num_blocks = data_length / 16;
    block_remainder = data_length % 16;

    printf("%s\n",label);

    for (i=0; i< num_blocks;i++)
    {
        printf("\t");
        for (j=0; j< 16;j++)
        {
            printf("%02x ", data[j + (i*16)]);
        }
        printf("\n");
    }

    if (block_remainder > 0)
    {
        printf("\t");
        for (j=0; j<block_remainder; j++)
        {
            printf("%02x ", data[j+(num_blocks*16)]);
        }
        printf("\n");
    }
}
#endif

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
#ifdef HMAC_DEBUG
    debug_out("k0",k0,64);
#endif
    /* Step 4 */
    for (i=0; i<64; i++)
    {
        k0xorIpad[i] = k0[i] ^ ipad;
    }
#ifdef HMAC_DEBUG
    debug_out("k0 xor ipad",k0xorIpad,64);
#endif
    /* Step 5 */
    for (i=0; i<64; i++)
    {
        step5data[i] = k0xorIpad[i];
    }
    for (i=0;i<data_length;i++)
    {
        step5data[i+64] = data[i];
    }
#ifdef HMAC_DEBUG
    debug_out("(k0 xor ipad) || text",step5data,data_length+64);
#endif

    /* Step 6 */
    sha1digest(digest, step5data, data_length+b);

#ifdef HMAC_DEBUG
    debug_out("Hash((k0 xor ipad) || text)",digest,20);
#endif

    /* Step 7 */
    for (i=0; i<64; i++)
    {
        step7data[i] = k0[i] ^ opad;
    }

#ifdef HMAC_DEBUG
    debug_out("(k0 xor opad)",step7data,64);
#endif

    /* Step 8 */
    for (i=0;i<64;i++)
    {
        step8data[i] = step7data[i];
    }
    for (i=0;i<20;i++)
    {
        step8data[i+64] = digest[i];
    }

#ifdef HMAC_DEBUG
    debug_out("(k0 xor opad) || Hash((k0 xor ipad) || text)",step8data,20+64);
#endif

    /* Step 9 */
    sha1digest(digest, step8data, b+20);

#ifdef HMAC_DEBUG
    debug_out("HASH((k0 xor opad) || Hash((k0 xor ipad) || text))",digest,20);
#endif
}