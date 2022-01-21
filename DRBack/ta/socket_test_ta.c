#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_socket.h>

#include <tee_isocket.h>
#include <tee_tcpsocket.h>

#include <socket_test_ta.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE_LENGTH 4096

struct page_buffer {
  unsigned char page_data[2048];
  unsigned int page_number;
  unsigned int version1;
  unsigned int version2;
};

struct socket_handle_t {
	int socket_handle;
	TEE_TASessionHandle sess;
};


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

// extern void hmac_sha1(unsigned char *digest, unsigned char *data, int data_length);

int string_cmp(unsigned char *s1, unsigned char *s2)
{
  int i;
  for (i = 0; s1[i] == s2[i]; i++)
    if (s1[i] == '\0')
      return 0;
  return s1[i] - s2[i];
}



TEE_UUID uuid = PTA_SOCKET_UUID;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG(" socket_test");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG(" socket_test");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;

	struct socket_handle_t *socket_handle;
	
	socket_handle = TEE_Malloc(sizeof(struct socket_handle_t *), 0);
	if (!socket_handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	socket_handle->socket_handle = 0;
	*sess_ctx = (void *)socket_handle;

	DMSG(" socket_test");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Free(socket_handle);

	DMSG(" socket_test");
}

static TEE_Result socket_open(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	err = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 
		0, NULL, &socket_handle->sess, &err_origin);
	
	if (err != TEE_SUCCESS)
		return err;

	TEE_Param op[4];

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);

	op[0].value.a = TEE_IP_VERSION_4;
	op[0].value.b = params[0].value.a;
	op[1].memref.buffer = params[1].memref.buffer;
	op[1].memref.size = params[1].memref.size;
	op[2].value.a = TEE_ISOCKET_PROTOCOLID_TCP;
	
	DMSG("\n  Open connection %s:%d",
		(char *) params[1].memref.buffer,
		params[0].value.a);


	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_OPEN,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	socket_handle->socket_handle = op[3].value.a;

	DMSG("\n  Success %s:%d, socket_handle: %d\n",
		(char *) params[1].memref.buffer,
		params[0].value.a,
		socket_handle->socket_handle);

	return TEE_SUCCESS;
}

static TEE_Result socket_close(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	/* Unused parameters */
	(void)&params;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	TEE_Param op[4];
	op[0].value.a = socket_handle->socket_handle;
	
	DMSG("\n  socket_handle: %d", socket_handle->socket_handle);

	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_CLOSE,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	TEE_CloseTASession(socket_handle->sess);
	socket_handle->socket_handle = 0;

	return TEE_SUCCESS;
}

static TEE_Result socket_send(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	// unsigned char buffer_with_address[2057];
	unsigned char data[2061];
  unsigned char sendbuff[2080];
  unsigned char digest[21];

	DMSG(" socket_test socket_send\n");

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT);

	
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	TEE_Param op[4];

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	// verify hmac-sha1
	// data = (char *)params[0].memref.buffer;
	// memset(data, 'a', 2060);
  memcpy(data, params[0].memref.buffer, 2060); 
  memcpy(sendbuff, params[0].memref.buffer, 2060); 
  memcpy(sendbuff+2060, params[2].memref.buffer, 20);

	// memcpy(buffer_with_address, params[0].memref.buffer, params[0].memref.size);
	// memcpy(buffer_with_address+2048, &params[2].value.a, 4);
  	// memcpy(buffer_with_address+2052, &params[3].value.a, 4);
  	// hmac_sha1(digest, buffer_with_address, 2056);

  
	hmac_sha1(digest, data, 2060);
	
	
	if (string_cmp(digest, params[2].memref.buffer)) {
  // if(0){
		params[1].value.a = 0;
	} else
	{
    op[0].value.a = socket_handle->socket_handle;
    op[0].value.b = TEE_TIMEOUT_INFINITE;
    op[1].memref.buffer = sendbuff;
    op[1].memref.size = sizeof(sendbuff);

    err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
      PTA_SOCKET_SEND,  ptypes, op, &err_origin);
    if (err != TEE_SUCCESS)
    {
      EMSG("\n  .Error: Socket send 0x%x", err);
      return err;
    }

		params[1].value.a = 1;
    // socket_send(socket_handle, "hello world", strlen("hello world"));
	}
	

	params[3].value.a = op[2].value.a;

	return TEE_SUCCESS;
}

static TEE_Result socket_recv(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	DMSG(" socket_test socket_recv\n");

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	TEE_Param op[4];
	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = TEE_TIMEOUT_INFINITE;
	op[1].memref.buffer = params[0].memref.buffer;
	op[1].memref.size = params[0].memref.size;
	
	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_RECV,  
		ptypes,
		op, &err_origin);

	if (err != TEE_SUCCESS)
	{
		EMSG("\n  .Error: Socket recv 0x%x", err);
		return err;
	}

	DMSG("\n  recv(%d bytes): %s", op[1].memref.size, (char *) op[1].memref.buffer);

	return TEE_SUCCESS;
}

static TEE_Result socket_ioctl(void *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	struct socket_handle_t *socket_handle = (struct socket_handle_t *)sess_ctx;
	TEE_Result err;
	uint32_t err_origin;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Param op[4];

	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	op[0].value.a = socket_handle->socket_handle;
	op[0].value.b = params[0].value.a;
	op[1].memref.buffer = params[1].memref.buffer;
	op[1].memref.size = params[1].memref.size;

	err = TEE_InvokeTACommand(socket_handle->sess, TEE_TIMEOUT_INFINITE,
		PTA_SOCKET_IOCTL,  
		ptypes,
		op, &err_origin);
	if (err != TEE_SUCCESS)
		return err;

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	DMSG("InvokeCommandEntryPoint id:%d", cmd_id);
	switch (cmd_id) {
	case TA_SOCKET_OPEN_CMD:
		return socket_open(sess_ctx, param_types, params);
	case TA_SOCKET_CLOSE_CMD:
		return socket_close(sess_ctx, param_types, params);
	case TA_SOCKET_SEND_CMD:
		return socket_send(sess_ctx, param_types, params);
	case TA_SOCKET_RECV_CMD:
		return socket_recv(sess_ctx, param_types, params);
	case TA_SOCKET_IOCTL_CMD:
		return socket_ioctl(sess_ctx, param_types, params);
	default:
		DMSG(" Socket_test Error\n  ! id:%d not exist", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
