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

#ifndef _MBED_LORAWAN_UPDATE_CLIENT_BDFILE
#define _MBED_LORAWAN_UPDATE_CLIENT_BDFILE

#include "FragmentationBlockDeviceWrapper.h"

// So, janpatch uses POSIX FS calls, let's emulate them, but backed by BlockDevice driver

class BDFILE {
public:
    /**
     * Creates a new BDFILE
     * @param _bd Instance of a BlockDevice
     * @param _offset Offset of the file in flash
     * @param _size Size of the file in flash
     */
    BDFILE(FragmentationBlockDeviceWrapper* _bd, size_t _offset, size_t _size);

    /**
     * Sets position in the file
     * @param pos New position
     * @param origin Seek position
     */
    int fseek(long int pos, int origin);

    size_t fread(void *buffer, size_t elements, size_t element_size) ;

    size_t fwrite(const void *buffer, size_t elements, size_t size);

    long int ftell() ;

private:
    FragmentationBlockDeviceWrapper* bd;
    size_t offset;
    size_t size;
    int current_pos;
};


int bd_fseek(BDFILE *file, long int pos, int origin);
long int bd_ftell(BDFILE *file);
size_t bd_fread(void *buffer, size_t elements, size_t size, BDFILE *file);
size_t bd_fwrite(const void *buffer, size_t elements, size_t size, BDFILE *file);


#endif // _MBED_LORAWAN_UPDATE_CLIENT_BDFILE

