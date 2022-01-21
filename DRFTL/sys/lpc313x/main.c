/*************************************************************************
*
*   Used with ICCARM and AARM.
*
*    (c) Copyright IAR Systems 2009
*
*    File name   : main.c
*    Description :
*
*
*COMPATIBILITY
*=============
*
*   The USB Mass storage example project is compatible with Embedded Artsists
*  LPC313x evaluation board. By default the project is configured to use the
*  J-Link JTAG interface.
*
*CONFIGURATION
*=============
*
*  The Project contains the following configurations:
*
*  Debug: run in iRAM
*
*
*    History :
*    1. Date        : 22.8.2009
*       Author      : Stanimir Bonev
*       Description : initial revision.
*
*    $Revision: 32285 $
**************************************************************************/

/** include files **/
#include "includes.h"

#include <NXP/iolpc3131.h>
#include <stdio.h>
#include <string.h>
#include "arm926ej_cp15_drv.h"
#include "arm_comm.h"
#include "drv_spi.h"
#include "drv_spinor.h"
#include "drv_intc.h"
#include "math.h"

#include "lpc313x_timer_driver.h"
#include "lpc313x_usbotg.h"
#include "lpc313x_usbd_driver.h"
#include "lpc313x_chip.h"
#include "mscuser.h"
#include "usbcore.h"
#include "usbhw.h"

#include <core\inc\ubi.h>
#include <onfm.h>
#include <core\inc\cmn.h>
#include <core\inc\buf.h>
#include <core\inc\mtd.h>
#include <core\inc\ftl.h>
//#include <core\polar\include\polarssl\aes.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
// #include <sys/stat.h>
#include <errno.h>
#include <math.h> 
#include <inttypes.h>

#define SDRAM_BASE_ADDR 0x30000000
#define SDRAM_SIZE      0x02000000

/** external functions **/
extern void InitSDRAM(void);

/** internal functions **/
extern void USB_EndPoint0 (UNS_32 event);


#pragma data_alignment=DMA_BURST_BYTES
unsigned char sector_buffer[SECTOR_SIZE];

#pragma data_alignment=DMA_BURST_BYTES
unsigned char read_sector_buffer[SECTOR_SIZE];

#pragma data_alignment=DMA_BURST_BYTES
UINT8 write_page_buffer[MPP_SIZE];
#pragma data_alignment=DMA_BURST_BYTES
UINT8 read_page_buffer[MPP_SIZE];

#define ISROM_MMU_TTBL              (0x1201C000)
#define USER_SPACE_SECTOR_COUNT     (ONFM_Capacity())


// extern int PMT_isvalid(PGADDR page_addr);

// static UINT8 test_buffer[MPP_SIZE];
// static UINT8 test_buffer[2048];
// static unsigned char test_string[2048];
// static char *back_up="backup_initial";
// static char *restore="restore_initial";
// static char *restore_f="restore_finished";
int backup_flag = 0;
int restore_flag = 0;
int initial_flag = 0;    // set after format

// typedef unsigned char uint8_t;

// extern int sha1digest(uint8_t *digest, const uint8_t *data, size_t databytes);

// extern void hmac_sha1(unsigned char *digest, unsigned char *data, int data_length);

typedef unsigned char *byte_pointer;
extern void show_bytes(byte_pointer start, int len);

// extern bool rsa1024(uint64_t res[], uint64_t data[], uint64_t expo[],uint64_t key[]);

// uint8_t digest[20];
// char hexdigest[41];
// char *hash_data;
// unsigned char * testdigest;

// int i0;
// uint64_t x[20]={0},z[20]={0},e[18]={0};
// uint8_t data[150]={0xB4,0x55,0x6A,0xBB,0xF1,0x68,0x88,0x98,0x46,0xE4,0xB8,0xC7,0xDA,0xB1,0xB7,0x7E,0x78,0x5F,0x73,0x51,0xC3,0x77,0x23,0x25,0x29,0x49,0xE0,0x66,0x6E,0x70,0x0D,0x1C,0x5F,0x9A,0xE7,0x01,0x7D,0x9C,0xEA,0x4E,0xA9,0x94,0xA5,0x3C,0xA0,0x36,0xA4,0x74,0xFD,0x44,0x95,0x4C,0xDD,0x4D,0x73,0x6D,0xC9,0x18,0xF0,0x99,0x79,0xE5,0x16,0x23,0x02,0xB2,0xA9,0x18,0xC0,0x7B,0x55,0x2F,0xD0,0xFC,0x0F,0x1C,0x67,0xAC,0x01,0x5C,0x12,0x1C,0x3B,0x7B,0x60,0xD8,0x8C,0x7E,0x34,0x2E,0x2D,0x86,0x3B,0x10,0x51,0x41,0x8C,0xCE,0x67,0xC5,0xE4,0x40,0xC4,0x44,0xF6,0xD5,0x9D,0xE3,0x3F,0x4E,0xC7,0x42,0xE0,0x83,0x6A,0x76,0x45,0x62,0xDD,0xF7,0x5D,0xAE,0x1B,0xB3,0x5E,0x1E,0xCD,0xDF};

// char msg[150] = {0};

// uint8_t y[150]={0x15,0xCA,0xFC,0xCB,0x19,0xB1,0x78,0x50,0x6E,0xC0,0xD5,0x53,0xD1,0xAA,0x08,0x72,0xD0,0x39,0x38,0xC6,0x78,0xC8,0xBD,0x06,0x90,0xA6,0xCC,0xE7,0x94,0x11,0x16,0x84,0x87,0x49,0x41,0x01,0x7D,0x1C,0xA9,0x74,0x38,0x2A,0x2E,0x8D,0xD5,0x0E,0xC5,0x71,0x1D,0xEA,0x5B,0xE0,0x9E,0x1D,0xEE,0x05,0x26,0x78,0x4D,0x1B,0x3F,0x0F,0xE0,0x4C,0xC6,0xBF,0x45,0xCA,0x17,0x16,0xB0,0xBC,0xB8,0xB9,0xF4,0xAC,0xAE,0xDB,0xFD,0xBA,0x05,0x40,0x2E,0xFA,0xBF,0xB4,0xF1,0x53,0x79,0x20,0x7C,0xC8,0xE5,0x84,0x81,0x46,0xAA,0xFD,0x47,0xA8,0x4D,0x14,0xDA,0x29,0xAF,0xA9,0x56,0x1E,0x6D,0xF0,0xC3,0x05,0xFF,0x57,0xF3,0xDB,0xFA,0x6B,0xA2,0x82,0x5C,0xDC,0xF4,0x00,0x59,0x2A,0x08,0x01};



/***********************************************************************
*
* Function: USB_Reset_Event
*
* Purpose: USB Reset Event Callback
*
* Processing:
*     Called automatically on USB Reset Event.
*
* Parameters: None
*
* Outputs: None
*
* Returns: Nothing
*
* Notes: None
*
***********************************************************************/
void USB_Reset_Event(void)
{
  USB_ResetCore();
}

#if USB_CONFIGURE_EVENT
/***********************************************************************
*
* Function: USB_Configure_Event
*
* Purpose: USB Configure Event Callback
*
* Processing:
*     Called automatically on USB configure Event.
*
* Parameters: None
*
* Outputs: None
*
* Returns: Nothing
*
* Notes: None
*
***********************************************************************/
void USB_Configure_Event (void)
{
  
}
#endif

/***********************************************************************
*
* Function: USB_EndPoint1
*
* Purpose: USB Endpoint 1 Event Callback
*
* Processing:
*     Called automatically on USB Endpoint 1 Event
*
* Parameters: None
*
* Outputs: None
*
* Returns: Nothing
*
* Notes: None
*
***********************************************************************/
void USB_EndPoint1 (UNS_32 event)
{
  switch (event)
  {
  case USB_EVT_OUT_NAK:
    MSC_BulkOutNak();
    break;
  case USB_EVT_OUT:
    MSC_BulkOut();
    break;
  case USB_EVT_IN_NAK:
    MSC_BulkInNak();
    break;
  case USB_EVT_IN:
    MSC_BulkIn();
    break;
  }
}


static void init_usb()
{
  LPC_USBDRV_INIT_T usb_cb;
  
  // Enable USB interrupts
  // Install Interrupt Service Routine, Priority
  INTC_IRQInstall(USB_ISR, IRQ_USB, USB_INTR_PRIORITY,0);
  
  /* initilize call back structures */
  memset((void*)&usb_cb, 0, sizeof(LPC_USBDRV_INIT_T));
  usb_cb.USB_Reset_Event = USB_Reset_Event;
  usb_cb.USB_P_EP[0] = USB_EndPoint0;
  usb_cb.USB_P_EP[1] = USB_EndPoint1;
  usb_cb.ep0_maxp = USB_MAX_PACKET0;
  /* USB Initialization */
  USB_Init(&usb_cb);
}

bool StartsWith(const char *a, const char *b)
{
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}

static void usb_user_task_loop()
{
  int pop;
  UNS_32 offset;
  UNS_32 length;
  
  uart_printf("start loop:\n");
  while (1)
  {  
    pop = ut_pop;
    //push = ut_push;
    //if (ut_pop != ut_push)
    if (pop != ut_push)
    {
      if (ut_list[pop].type == UT_WRITE)
      {
        // uart_printf("offset is %d, length is %d:\n", ut_list[pop].offset, ut_list[pop].length);
               
     
        LED_SET(LED2);

        ONFM_Write(ut_list[pop].offset,
                   ut_list[pop].length,
                   ut_list[pop].buffer);
        
        LED_CLR(LED2);
        
        
      }
      else if (ut_list[pop].type == UT_READ)
      {
        if (Read_BulkLen == 0)
        {
          LED_SET(LED1);
          
          offset = ut_list[pop].offset;
          length = ut_list[pop].length;
          
          /*
          if(offset == 800000){
            uart_printf("main lenght is %d\n", length);
          }
          */
          

          ONFM_Read(offset,
                    length,
                    ut_list[pop].buffer);
          
          LED_CLR(LED1);
          
          /* tell the IN NAK INT the buffer is ready to prime */
          Read_BulkLen = (ut_list[pop].length)*MSC_BlockSize;
        }
      }
      else
      {
        ASSERT(ut_list[pop].type == UT_MERGE);
        
        if (merge_stage == MERGE_START)
        {
          ONFM_Read(ut_list[pop].offset,
                    ut_list[pop].length,
                    ut_list[pop].buffer);
          
          merge_stage = MERGE_FINISH;
        }
      }
      
      /* next write operation */
      ut_pop = (ut_pop+1)%UT_LIST_SIZE;
    }
  }
}

static void SDRAM_Test(void)
{
char s[64];
  sprintf(s,"\n\rStart SDRAM Test\n\r");  
  UartWrite((unsigned char *)s,strlen(s));

  /*32bit access test*/
  sprintf(s,"32-bits write\n\r");
  UartWrite((unsigned char *)s,strlen(s));
  /*Start from stram base address*/
  volatile unsigned int * uint_dest = (unsigned int *)SDRAM_BASE_ADDR;
  for(int i = 0; i < SDRAM_SIZE/sizeof(int); i++,uint_dest++)
  {
    /*32-bits write*/
    * uint_dest = i;
  }
  /*32-bits verify*/
  sprintf(s,"32-bits verify\n\r");
  UartWrite((unsigned char *)s,strlen(s));

  uint_dest = (unsigned int *)SDRAM_BASE_ADDR;
  for(int i = 0; i < SDRAM_SIZE/sizeof(int); i++,uint_dest++)
  {
    /*32-bits read*/
    if (* uint_dest != i)
    {
      /*verify error*/
      sprintf(s,"SDRAM 32-bits R/W Error at address %0x\n\r",(unsigned int)uint_dest);
      UartWrite((unsigned char *)s,strlen(s));
      break;
    }
  }
  
  /*16-bits access test*/
  sprintf(s,"16-bits write\n\r");
  UartWrite((unsigned char *)s,strlen(s));
  /*Start from stram base address*/
  volatile unsigned short * ushrt_dest = (unsigned short *)SDRAM_BASE_ADDR;
  for(int i = 0; i < SDRAM_SIZE/sizeof(short); i++,ushrt_dest++)
  {
    /*16-bits write*/
    *ushrt_dest = (i^(i>>16));
  }
  /*16-bits verify*/
  sprintf(s,"16-bits verify\n\r");
  UartWrite((unsigned char *)s,strlen(s));

  ushrt_dest = (unsigned short *)SDRAM_BASE_ADDR;
  for(int i = 0; i < SDRAM_SIZE/sizeof(short); i++,ushrt_dest++)
  {
    /*16-bits read*/
    if ( *ushrt_dest != ((i^(i>>16))&0xFFFF))
    {
      /*verify error*/
      sprintf(s,"SDRAM 16-bits R/W Error at address 0x%0x\n\r",(unsigned int)ushrt_dest);
      UartWrite((unsigned char *)s,strlen(s));
      break;
    }
  }
  
  /*8-bits access test*/
  sprintf(s,"8-bits write\n\r");
  UartWrite((unsigned char *)s,strlen(s));
  /*Start from stram base address*/
  volatile unsigned char * uchar_dest = (unsigned char *)SDRAM_BASE_ADDR;
  for(int i = 0; i < SDRAM_SIZE; i++,uchar_dest++)
  {
    /*16-bits write*/
    *uchar_dest = i^(i>>8);
  }
  /*8-bits verify*/
  sprintf(s,"8-bits verify\n\r");
  UartWrite((unsigned char *)s,strlen(s));

  uchar_dest = (unsigned char *)SDRAM_BASE_ADDR;
  for(int i = 0; i < SDRAM_SIZE; i++,uchar_dest++)
  {
    /*8-bits read*/
    if ( *uchar_dest != ((i^(i>>8))&0xFF))
    {
      /*verify error*/
      sprintf(s,"SDRAM 8-bits R/W Error at address %0x\n\r",(unsigned int)ushrt_dest);
      UartWrite((unsigned char *)s,strlen(s));
      break;
    }
  }

  sprintf(s,"SDRAM Test end\n\r");  
  UartWrite((unsigned char *)s,strlen(s));

}

/*************************************************************************
* Function Name: main
* Parameters: None
*
* Return: None
*
* Description: Getting Started main loop
*
*************************************************************************/
void main(void)
{
  int onfm_ret = 0;
 #if 0 
  CP15_Mmu(FALSE);            // Disable MMU
  CP15_ICache(TRUE);          // Enable ICache

  CP15_SysProt(FALSE);
  CP15_RomProt(TRUE);
  CP15_SetTtb((Int32U *)ISROM_MMU_TTBL);  //Set translation table base address
  CP15_SetDomain( (DomainManager << 2*1) | (DomainClient << 0)); // Set domains
  CP15_Mmu(TRUE);             // Enable MMU
  CP15_Cache(TRUE);           // Enable ICache,DCache
#endif  
  
#ifndef BOOT_LEVEL_2
  InitClock();
  InitSDRAM();
  InitSPINOR();
#endif
  

  // Uncomment for SDRAM experiment.
   InitSDRAM();

  /* TODO:
  * - test DMA copy in SDRAM w/ and w/o clock enable.
  * - test USB RAMDisk speed
  * - test mtd speed
  * - test ONFM-USB
  * - debug, use K9HAG.
  */
  
  /*Init Interrupt Controller.
  Arm Vector Copy to beginnint of the IRAM*/
  INTC_Init((Int32U *)ISRAM_ESRAM0_BASE);
  /*Remap IRAM at address 0*/
  SYSCREG_ARM926_901616_LP_SHADOW_POINT = ISRAM_ESRAM0_BASE;
  
  init_usb();
  
  // Uncomment for SDRAM experiment.
  //SDRAM_Test();
  
  //jsj修改
  //原来是只执行ONFM_Mount()，若成功就不执行ONFM_Format()了，使得不必每次下载完代码都需要格式化文件系统
  //现在改成先执行ONFM_Format()，再执行ONFM_Mount()，这样每次下载完代码都需要格式化文件系统
  
  /* init ONFM */  
  //onfm_ret = ONFM_Mount();
  onfm_ret = -1;
  if (onfm_ret != 0) {
    /* init failed, try to format */
    onfm_ret = ONFM_Format();
    if (onfm_ret == 0) {
      onfm_ret = ONFM_Mount();
    }
  }
  
  if (onfm_ret == 0) {
    MSC_Init();
    
    // Enable USB interrupt
    INTC_IntEnable(IRQ_USB, 1);
    __enable_irq();
    
    /* wait */
    timer_wait_ms(NULL, 10);
     
    
    /* USB Connect */
    USB_Connect(TRUE);
    uart_printf("usb connect\n");
  }    
  
  //jsj 运行到此时提示格式化文件系统
    
  
  // write test data
  /*
  for(int i=0;i<2047;i++){
    test_string[i]='a';
  }
  
  FTL_Write(4000, test_string);
  FTL_Read(4000, test_buffer);
  //for(int i=0;i<10;i++){
    uart_printf("%s\n", test_buffer);
  //}
  */
  
  
  /* test sha-1 and hmac-sha-1 */
  /* 
  hash_data = "The quick brown fox jumps over the lazy dog";
  
  if (sha1digest(digest, hash_data, strlen(data)))
 {
    uart_printf ("Error with sha1digest()\n");
 } else {
    // bin_to_strhex(digest, 20, &testdigest);
    uart_printf ("hex_digest:   '%s'\n",  digest);
    show_bytes(digest, 20);
 }
  
 hash_data = "b";
 hmac_sha1(digest, hash_data, strlen(hash_data));
 show_bytes(digest, 20);
 */
  
  
  /* main loop to handle usb read/write tasks in USER SPACE */
  usb_user_task_loop();
  
 
      
  /* TODO: call unmount to flush and check program status
  * periodly after a long time delay. Avoid PLR or unsafe plug-out
  */
  ONFM_Unmount();
  
  /* TODO: use watchdog timer, to reset system */
}
