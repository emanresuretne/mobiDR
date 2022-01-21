#ifndef TA_SOCKET_TEST_H
#define TA_SOCKET_TEST_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_SOCKET_TEST_UUID \
	{ 0x84a7e37d, 0x9583, 0x4eb0, \
		{ 0x94, 0xbc, 0xcf, 0xd4, 0x16, 0x14, 0x8f, 0xa8} }
	
/* The function IDs implemented in this TA */

/*
 * TA_SOCKET_OPEN_CMD
 * [INPUT] 	param[0].value.a - port
 * [INPUT] 	param[1] (memref) - server address
 * 			param[2] unused
 * 			param[3] unused
 */
#define TA_SOCKET_OPEN_CMD 0

/*
 * TA_SOCKET_CLOSE_CMD
 * param[0] unused
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SOCKET_CLOSE_CMD 1

/*
 * TA_SOCKET_SEND_CMD
 * [INPUT] 	param[0] (memref) - message
 * [OUTPUT] param[1].value.a - bytes sent
 * 			param[2] unused
 * 			param[3] unused
 */
#define TA_SOCKET_SEND_CMD 2

/*
 * TA_SOCKET_RECV_CMD
 * [OUTPUT] param[0] (memref) - message
 * 			param[1] unused
 * 			param[2] unused
 * 			param[3] unused
 */
#define TA_SOCKET_RECV_CMD 3

/*
 * TA_SOCKET_IOCTL_CMD
 * [INPUT] 	param[0].value.a - command ioctl
 * [INOUT] param[0] (memref) - buffer
 * 			param[2] unused
 * 			param[3] unused
 */
#define TA_SOCKET_IOCTL_CMD 4


#endif /*TA_SOCKET_TEST_H*/
