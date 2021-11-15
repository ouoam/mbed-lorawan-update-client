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

#include "BDFile.h"
#include "Z_ARI_FILE.h"

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
int copy_flash_to_blockdevice(const uint32_t flash_page_size, size_t flash_address, size_t flash_size, FragmentationBlockDeviceWrapper *bd, size_t bd_address);

/**
 * Print large block of data on a block device
 * @param bd Instance of block device
 * @param address Start address
 * @param length Amount of bytes to print
 * @param buffer_size Buffer size to allocate
 * @returns 0 if OK, negative value if not OK
 */
int print_blockdevice_content(FragmentationBlockDeviceWrapper *bd, size_t address, size_t length, size_t buffer_size);

void patch_progress_callback(void);

/**
 * Apply the delta update w/ decompression
 * @param bd BlockDevice instance
 * @param buffer_size Size of the r/w buffer. Note that this will be alocated two times!
 * @param source Source file on block device
 * @param patch  Patch file on block device
 * @param target Target file on block device
 * @returns 0 if OK, a negative value if not OK
 */
int apply_delta_update_compressed(FragmentationBlockDeviceWrapper *bd, size_t buffer_size,BDFILE *source, Z_ARI_FILE *patch, BDFILE *target);



/**
 * Apply the delta update
 * @param bd BlockDevice instance
 * @param buffer_size Size of the r/w buffer. Note that this will be alocated three times!
 * @param source Source file on block device
 * @param patch  Patch file on block device
 * @param target Target file on block device
 * @returns 0 if OK, a negative value if not OK
 */
int apply_delta_update(FragmentationBlockDeviceWrapper *bd, size_t buffer_size, BDFILE *source, BDFILE *patch, BDFILE *target);

#endif // _MBED_LORAWAN_UPDATE_CLIENT_DELTA_UPDATE
