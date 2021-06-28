/*
* PackageLicenseDeclared: Apache-2.0
* Copyright (c) 2018 ARM Limited
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/**
 * Some functions that are handy when implementing delta updates
 */

#ifndef _MBED_LORAWAN_UPDATE_CLIENT_DELTA_UPDATE
#define _MBED_LORAWAN_UPDATE_CLIENT_DELTA_UPDATE

#include "mbed.h"
#include "BDFile.h"
#include "Z_ARI_FILE.h"
#include "ddelta.h"     //MODIFIED
#include "janpatch.h" 

#include "FragmentationBlockDeviceWrapper.h"
#include "FlashIAP.h"

#include "mbed_memory_status.h"

#include "mbed_trace.h"
#ifndef TRACE_GROUP
#undef TRACE_GROUP
#endif
#define TRACE_GROUP "DLTA"

enum MBED_DELTA_UPDATE {
    MBED_DELTA_UPDATE_OK        = 0,
    MBED_DELTA_UPDATE_NO_MEMORY = -8401
};

/**
 * Copy the content of the current running application to a block device
 * @param flash_page_size Size of a flash page, will also be allocated as a buffer
 * @param flash_address Start of the application
 * @param flash_size Size of the application
 * @param bd Instance of block device
 * @param bd_address Offset for block device to store the application in
 * @returns 0 if OK, negative value if not OK
 */
int copy_flash_to_blockdevice(const uint32_t flash_page_size, size_t flash_address, size_t flash_size, FragmentationBlockDeviceWrapper *bd, size_t bd_address) {
    int r;

    FlashIAP flash;
    if ((r = flash.init()) != 0) {
        return r;
    }

    char *page_buffer = (char*)malloc(flash_page_size);
    if (!page_buffer) {
        return MBED_DELTA_UPDATE_NO_MEMORY;
    }

    int bytes_left = (int)flash_size;

    int prv_pct = 0;

    while (bytes_left > 0) {
        int to_read = flash_page_size;
        if (to_read > bytes_left) to_read = bytes_left;

        // copy it over
        int v = flash.read(page_buffer, flash_address, to_read);
        if (v != 0) {
            free(page_buffer);
            return r;
        }
        bd->program(page_buffer, bd_address, to_read);

        int pct = ((flash_size - bytes_left) * 100) / flash_size;
        if (pct != prv_pct) {
            tr_debug("Copying from flash to blockdevice: %u%%", ((flash_size - bytes_left) * 100) / flash_size);

            prv_pct = pct;
        }

        bytes_left -= to_read;
        bd_address += to_read;
        flash_address += to_read;
    }

    free(page_buffer);

    if ((r = flash.deinit()) != 0) {
        return r;
    }

    tr_debug("Copying from flash to blockdevice: 100%%");
    return MBED_DELTA_UPDATE_OK;
}

/**
 * Print large block of data on a block device
 * @param bd Instance of block device
 * @param address Start address
 * @param length Amount of bytes to print
 * @param buffer_size Buffer size to allocate
 * @returns 0 if OK, negative value if not OK
 */
int print_blockdevice_content(FragmentationBlockDeviceWrapper *bd, size_t address, size_t length, size_t buffer_size) {
    uint8_t *buffer = (uint8_t*)malloc(buffer_size);
    if (!buffer) {
        return MBED_DELTA_UPDATE_NO_MEMORY;
    }

    size_t offset = address;
    size_t bytes_left = length;

    while (bytes_left > 0) {
        size_t length = buffer_size;
        if (length > bytes_left) length = bytes_left;

        bd->read(buffer, offset, length);

        for (size_t ix = 0; ix < length; ix++) {
            printf("%02x", buffer[ix]);
        }

        offset += length;
        bytes_left -= length;
    }

    printf("\n");

    free(buffer);

    return MBED_DELTA_UPDATE_OK;
}

static void patch_progress(uint8_t pct) {
    static uint8_t last_patch_pct = 0;

    if (last_patch_pct != pct) {
        tr_debug("Patch progress: %d%%", pct);
        last_patch_pct = pct;
    }
}

/**
 * Apply the delta update w/ decompression
 * @param bd BlockDevice instance
 * @param buffer_size Size of the r/w buffer. Note that this will be alocated two times!
 * @param source Source file on block device
 * @param patch  Patch file on block device
 * @param target Target file on block device
 * @returns 0 if OK, a negative value if not OK
 */
int apply_delta_update_compressed(FragmentationBlockDeviceWrapper *bd, size_t buffer_size,BDFILE *source, Z_ARI_FILE *patch, BDFILE *target) {
    struct ddelta_header header;
    uint8_t ret;
    #if DO_MEMORY_PRINT==1
    tr_debug("Before Header Read");
    print_all_thread_info();
    print_heap_and_isr_stack_info();
    #endif

    if (ret = ddelta_header_read(&header, patch) < 0){
        tr_debug("NOT a ddelta file sent (error %d)",ret);
        return -1;
    }
    //tr_debug("header read, new fw will be : %d",header.new_file_size);

    #if DO_MEMORY_PRINT==1
    tr_debug("Before ddelta apply");
    print_all_thread_info();
    print_heap_and_isr_stack_info();
    #endif

    ddelta_apply(&header, patch, source, target);

    return 0;
}



/**
 * Apply the delta update
 * @param bd BlockDevice instance
 * @param buffer_size Size of the r/w buffer. Note that this will be alocated three times!
 * @param source Source file on block device
 * @param patch  Patch file on block device
 * @param target Target file on block device
 * @returns 0 if OK, a negative value if not OK
 */
int apply_delta_update(FragmentationBlockDeviceWrapper *bd, size_t buffer_size, BDFILE *source, BDFILE *patch, BDFILE *target) {
    unsigned char *source_buffer = (unsigned char*)malloc(buffer_size);
    if (!source_buffer) {
        return MBED_DELTA_UPDATE_NO_MEMORY;
    }
    unsigned char *patch_buffer = (unsigned char*)malloc(buffer_size);
    if (!patch_buffer) {
        free(source_buffer);
        return MBED_DELTA_UPDATE_NO_MEMORY;
    }
    unsigned char *target_buffer = (unsigned char*)malloc(buffer_size);
    if (!target_buffer) {
        free(source_buffer);
        free(patch_buffer);
        return MBED_DELTA_UPDATE_NO_MEMORY;
    }

    janpatch_ctx ctx = {
        { source_buffer, buffer_size },
        { patch_buffer,  buffer_size },
        { target_buffer, buffer_size },

        &bd_fread,
        &bd_fwrite,
        &bd_fseek,
        &bd_ftell,

        &patch_progress
    };

    int j = janpatch(ctx, source, patch, target);

    free(source_buffer);
    free(patch_buffer);
    free(target_buffer);

    return j;
}

#endif // _MBED_LORAWAN_UPDATE_CLIENT_DELTA_UPDATE
