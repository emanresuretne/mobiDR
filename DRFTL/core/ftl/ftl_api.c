/*********************************************************
 * Module name: ftl_api.c
 *
 * Copyright 2010, 2011. All Rights Reserved, Crane Chu.
 *
 * This file is part of OpenNFM.
 *
 * OpenNFM is free software: you can redistribute it and/or 
 * modify it under the terms of the GNU General Public 
 * License as published by the Free Software Foundation, 
 * either version 3 of the License, or (at your option) any 
 * later version.
 * 
 * OpenNFM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied 
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
 * PURPOSE. See the GNU General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with OpenNFM. If not, see 
 * <http://www.gnu.org/licenses/>.
 *
 * First written on 2010-01-01 by cranechu@gmail.com
 *
 * Module Description:
 *    FTL APIs.
 *
 *********************************************************/

#include <core\inc\cmn.h>
#include <core\inc\ftl.h>
#include <core\inc\ubi.h>
//#include <core\inc\mtd.h>
#include <sys\sys.h>
#include "ftl_inc.h"
#include <core\inc\buf.h>
#include <string.h>
   
#include <stdint.h>
#include <stdlib.h>

/* Advanced Page Mapping FTL:
 * - Block Dirty Table: LOG_BLOCK 0, cache all
 * - ROOT Table: LOG_BLOCK 1, cache all. point to journal blocks.
 * - Page Mapping Table: LOG_BLOCK 2~N, cache x pages with LRU algo.
 * - DATA Journal: commit
 * - Init: read BDT, ROOT, PMT, Journal info, ...
 * - Reclaim
 * - Meta Data Page: in last page in PMT blocks and data blocks.
 * - choose journal block on erase and write, according to die index
 *
 * TODO: advanced features:
 * - sanitizing
 * - bg erase
 * - check wp/trim, ...
 */

extern int backup_flag; 
extern int restore_flag;
extern int initial_flag;
// static int loop_count = 0;
int max_records = 0;
static int isodd = 1;
static int isodd2 = 1;
static UINT32 read_address = 0;
static UINT32 write_address = 0;
extern int PMT_isvalid(PGADDR page_addr);
PHY_BLOCK start_record_block = RECORD_START_BLOCK;
PHY_BLOCK current_record_block = RECORD_START_BLOCK;
PAGE_OFF current_record_page = 0;
UINT32 record_cache_page[512] = {0};
UINT32 record_index = 0;
static int backup_version = 0;
static int page_version = 0;
uint8_t digest[20];

extern UINT8 wear_l[4096];
static int current_state=0;

typedef unsigned char *byte_pointer;
// typedef unsigned char uint8_t;

// extern int sha1digest(uint8_t *digest, const uint8_t *data, size_t databytes);
extern void hmac_sha1(unsigned char *digest, unsigned char *data, int data_length);

extern STATUS Threshold_DATA_Reclaim(void);

void show_bytes(byte_pointer start, int len) {
    int i;
    for (i = 0; i < len; i++)
    uart_printf(" %x", start[i]);    //line:data:show_bytes_printf
    uart_printf("\n");
}
   
STATUS FTL_Format() {
  STATUS ret;
    
  ret = UBI_Format();
  if (ret == STATUS_SUCCESS) {
    ret = UBI_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = DATA_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = HDI_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = PMT_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = BDT_Format();
  }

  if (ret == STATUS_SUCCESS) {
    ret = ROOT_Format();
  }

  return ret;
}

STATUS FTL_Init() {
  STATUS ret;

  ret = UBI_Init();
  if (ret == STATUS_SUCCESS) {
    /* scan tables on UBI, and copy to RAM */
    ret = ROOT_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = BDT_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = PMT_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = HDI_Init();
  }

  if (ret == STATUS_SUCCESS) {
    ret = DATA_Replay(root_table.hot_journal);
  }

  if (ret == STATUS_SUCCESS) {
    ret = DATA_Replay(root_table.cold_journal);
  }

  if (ret == STATUS_SUCCESS) {
    /* handle reclaim PLR: start reclaim again. Some data should
     * be written in the same place, so just rewrite same data in the
     * same page regardless this page is written or not. */

    /* check if hot journal blocks are full */
    if (DATA_IsFull(TRUE) == TRUE) {
      ret = DATA_Reclaim(TRUE);
      if (ret == STATUS_SUCCESS) {
        ret = DATA_Commit();
      }
    }

    /* check if cold journal blocks are full */
    if (DATA_IsFull(FALSE) == TRUE) {
      ret = DATA_Reclaim(FALSE);
      if (ret == STATUS_SUCCESS) {
        ret = DATA_Commit();
      }
    }
  }

  return ret;
}

STATUS FTL_Write(PGADDR addr, void* buffer) {
  STATUS ret;
  BOOL is_hot = HDI_IsHotPage(addr);
  UINT32 i = 0;
  
  ret = DATA_Write(addr, buffer, is_hot);
  
  /*
  if(addr == 240010){
     backup_flag = 1 - backup_flag;
     uart_printf("backup flag is %d:\n", backup_flag);
  } else if(addr == 240020){
     restore_flag = 1 - restore_flag;
     uart_printf("restore flag is %d:\n", restore_flag);
  } else if(addr == 240030){
     initial_flag = 1 - initial_flag;
     uart_printf("initial flag is %d:\n", initial_flag);
  }
  */
  
  if (current_state == 0){
    if(addr == 240010){
      current_state = 1;
    }
  } else if(current_state == 1){
    if(addr == 240020){
      current_state = 2;
    } else {
      current_state = 0;
    }
  } else if(current_state == 2){
    if(addr == 240030){
      current_state = 3;
    } else {
      current_state = 0;
    }
  } else if(current_state == 3){
    if(addr == 240040){
      current_state = 4;
    } else {
      current_state = 0;
    }
  } else {
    if(addr == 240014){
      backup_flag = 1 - backup_flag;
      uart_printf("backup flag is %d:\n", backup_flag);
    } else if(addr == 240024){
      restore_flag = 1 - restore_flag;
      uart_printf("restore flag is %d:\n", restore_flag);
    } else if(addr == 240034){
      initial_flag = 1 - initial_flag;
      uart_printf("initial flag is %d:\n", initial_flag);
      for(i=0;i<4096;i++){
        uart_printf("wear leveling of block %d is %d:\n", i, wear_l[i]);
      }
    }
    current_state = 0;
  }
  
  if (ret == STATUS_SUCCESS) {
    if (DATA_IsFull(is_hot) == TRUE) {
      ret = DATA_Reclaim(is_hot);
      if (ret == STATUS_SUCCESS) {
        ret = DATA_Commit();
      }
    }
  }
  
  
  
  // uart_printf("FTL_Write:   %d\n",addr);
  // uart_printf("FTL_Write:   %d,   %x\n",addr, *((unsigned char*)buffer));
  // show_bytes(buffer, 2048); 
  // uart_printf("backup flag:  %d\n", backup_flag);
  
  return ret;
}

STATUS FTL_Read(PGADDR addr, void* buffer) {
  LOG_BLOCK block;
  PAGE_OFF page;
  STATUS ret;
  SPARE spare;
  LOG_BLOCK next_block = INVALID_BLOCK;
  
  char * const teststring = "Backup finished";
  unsigned char buffer_with_address[2060];
  
  
  if (addr==240000 && backup_flag){  // 判断是否读取备份数据
    if (isodd){ // 判断是返回 page 数据还是 page number
    // uart_printf("special read address\n");
    //  uart_printf("record_index=%d\n", record_index);   //record_index: 当前SDRAM中FTL_write的index，备份从此开始
    if (record_index==0){  //SDRAM中FTL_write记录全部备份完，从Flash中读取之前的记录
      uart_printf("record_index=0\n");
      if ((current_record_block == RECORD_START_BLOCK) && (current_record_page == 0)){  // 所有FTL_write记录全部备份完(包括SDRAM和Flash)，备份结束
        uart_printf("backup finished\n");
        memcpy(buffer, teststring, SECTOR_SIZE);
        backup_flag = 0;
        backup_version += 1;
        page_version = 0;
        
        ret = UBI_Erase(RECORD_START_BLOCK, RECORD_START_BLOCK);
        
        // 垃圾回收(need to be filled)
        // ret = STATUS_SUCCESS;        
        ret = Threshold_DATA_Reclaim();
        if (ret == STATUS_SUCCESS) {
          ret = DATA_Commit();
        }
        
        return ret;
      }
      else{
        uart_printf("load record\n");
        uart_printf("current_record_block=%d, current_record_page=%d\n", current_record_block, current_record_page);
        if (current_record_page == 0) {
            next_block = current_record_block - 1;
            current_record_page = 64;
            ret = UBI_Erase(current_record_block, current_record_block);
            if (ret == STATUS_SUCCESS) {
            current_record_block = next_block;
          }
        }
        ret = UBI_Read(current_record_block, current_record_page-1, record_cache_page, NULL); //从Flash中读取之前的记录
        current_record_page--;
        record_index = 512;  
      }
   }
   block = PM_NODE_BLOCK(record_cache_page[record_index-1]);
   page = PM_NODE_PAGE(record_cache_page[record_index-1]);
   // uart_printf("block=%d, page=%d\n", block, page);
   ret = UBI_Read(block, page, buffer, spare);
   record_index--;
   read_address = spare[0];
   isodd = 0;
   // compute hash
   memcpy(buffer_with_address, (unsigned char*)buffer, 2048);
   memcpy(buffer_with_address+2048, &read_address, 4);
   memcpy(buffer_with_address+2052, &backup_version, 4);
   memcpy(buffer_with_address+2056, &page_version, 4);
   hmac_sha1(digest, buffer_with_address, 2060);
   
   // show_bytes(buffer_with_address, 2060);                
   return ret;    
  }
  else {
   memcpy(buffer, &read_address, 4);
   memcpy((unsigned char*)buffer+4, &backup_version, 4);
   memcpy((unsigned char*)buffer+8, &page_version, 4);
   memcpy((unsigned char*)buffer+12, digest, 20);
   memset((unsigned char*)buffer+32, 0, 2024);
   // show_bytes(digest, 20);
   isodd = 1;
   page_version += 1;
   ret = STATUS_SUCCESS;
   // buffer = buffer +4;
   return ret;
  }
  }
  
  
  
  // uart_printf("before pmt search\n");
  ret = PMT_Search(addr, &block, &page);
  // uart_printf("pmt search, %d, %d\n",block,page);
  
  if (ret == STATUS_SUCCESS) {
    ret = UBI_Read(block, page, buffer, NULL);
    // uart_printf("ubi read\n");
  } 
  

  //if (addr != 240000){
    //uart_printf("FTL_Read:   %d\n",addr);
    // show_bytes((unsigned char*)buffer, 2048);
    // uart_printf("backup flag:  %d\n", backup_flag);
  //}
  
  return ret;
}

STATUS FTL_Trim(PGADDR start, PGADDR end) {
  PGADDR addr;
  STATUS ret = STATUS_SUCCESS;

  for (addr = start; addr <= end; addr++) {
    ret = FTL_Write(addr, NULL);
    if (ret != STATUS_SUCCESS) {
      break;
    }
  }

  return ret;
}

STATUS FTL_SetWP(PGADDR laddr, BOOL enabled) {
  return STATUS_FAILURE;
}

BOOL FTL_CheckWP(PGADDR laddr) {
  return FALSE;
}

STATUS FTL_BgTasks() {
  return STATUS_SUCCESS;
}

PGADDR FTL_Capacity() {
  LOG_BLOCK block;

  block = UBI_Capacity;//3989
  block -= JOURNAL_BLOCK_COUNT; /* data hot journal *///1
  block -= JOURNAL_BLOCK_COUNT; /* data cold journal *///1
  block -= JOURNAL_BLOCK_COUNT; /* data reclaim journal *///1
  block -= PMT_BLOCK_COUNT; /* pmt blocks *///40
  block -= 2; /* bdt blocks */
  block -= 2; /* root blocks */
  block -= 2; /* hdi reserved */
  
  // block -= 8; // reserved to hold records of FTL_write
  
  block -= block / 100 * OVER_PROVISION_RATE; /* over provision */
  
  uart_printf("%s: UBI_Capacity=%d\r\n",__func__,UBI_Capacity);
  uart_printf("%s: actual user capacity: block=%d\r\n",__func__,block);//3823

  /* last page in every block is reserved for meta data collection */
  return block * (PAGE_PER_PHY_BLOCK - 1);//471
}

STATUS FTL_Flush() {
  STATUS ret;

  ret = DATA_Commit();
  if (ret == STATUS_SUCCESS) {
    ret = UBI_Flush();
  }

  if (ret == STATUS_SUCCESS) {
    ret = UBI_SWL();
  }

  return ret;
}
