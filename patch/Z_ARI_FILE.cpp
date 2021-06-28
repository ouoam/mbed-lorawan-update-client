/**
 * 
 * ARTHUR M
 * 
 */

#include "Z_ARI_FILE.h"

#include "mbed_trace.h"

#ifndef TRACE_GROUP
#define TRACE_GROUP "UZAR" //UNZIP ARITMETIC
#endif



Z_ARI_FILE::Z_ARI_FILE(FragmentationBlockDeviceWrapper* _bd, size_t _offset, size_t _size) :
    bd(_bd), offset(_offset), size_z(_size), current_pos_unz(0)
    {  
        buffer_z_file = NULL;
        _init_decompressor_stream();
    }

/**
 * Destructor, frees buffer memory
 * 
 */
Z_ARI_FILE::~Z_ARI_FILE(){
    free(buffer_z_file);
}

/**
 * Offsets the uncompressed stream
 * @param pos the offset to consider
 * @param origin the reference point
 * Note : Only allows for Positive offset from current SEEK_CUR pos
 * @return 0 if success or -1 if failed
 */
int Z_ARI_FILE::fseek(long int pos, int origin) {
    switch (origin) {
        case SEEK_SET: { // from beginning
            return -1;
            break;
        }
        case SEEK_CUR: {
            if(pos<0){
                return -1; //only allow positive movement
            }else{
                int index = 0;
                //offesets for pos
                while (index < pos){
                    DecompressArithmeticSymbol(&arithmeticState);
                    index++;
                }
            }
            current_pos_unz += pos;
            break;
        }
        case SEEK_END: {
            return -1;
            break;
        }
        default: return -1;
    }

    if (static_cast<size_t>(current_pos_unz) > size_unz) return -1;
    return 0;
}

/**
 * Reads bytes from the decompressed stream
 * @param out ptr to buffer output
 * @param elements nb of elements to fetch
 * @param element_size size of elements to fetch
 * Note : reads elements*elements_size bytes 
 */
size_t Z_ARI_FILE::fread(void *out, size_t elements, size_t element_size) {
    uint8_t * buf = (uint8_t *) out;
    size_t index = 0;
    uint32_t symbol;
    while (index < elements*element_size){
        symbol = DecompressArithmeticSymbol(&arithmeticState);
        buf[index] = symbol;
        index++;
    }
    current_pos_unz += ( elements * element_size );
    return ( elements * element_size );
}

/**
 * NOT IMPLEMENTED
 */
size_t Z_ARI_FILE::fwrite(const void *buffer, size_t elements, size_t size) {
    return -1;
}

/**
 * Returns the position in the uncompressed file
 */
long int Z_ARI_FILE::ftell() {
    return current_pos_unz;
}

void Z_ARI_FILE::_init_decompressor_stream(void){
    bd->init();
    tr_debug("Size to allocation for decompression : %d",size_z);
    buffer_z_file = (uint8_t *) malloc(size_z);
    if(buffer_z_file==NULL){
        tr_debug("Cannot allocate that much memory");
        tr_debug("FAIL");
        //break;
    }else{
        tr_debug("Allocation success, from %p",buffer_z_file);
    }

    
    if( bd->read(buffer_z_file,offset,size_z) != BD_ERROR_OK){
        tr_debug("Cannot read that memory from bd");
        tr_debug("FAIL");
        //break;
    }

    
    size_unz = DecompressArithmeticStart(&arithmeticState,(uint8_t*) buffer_z_file, size_z); 

}
// Functions similar to the POSIX functions
int z_ari_fseek(Z_ARI_FILE *file, long int pos, int origin) {
    return file->fseek(pos, origin);
}

long int z_ari_ftell(Z_ARI_FILE *file) {
    return file->ftell();
}

size_t z_ari_fread(void *buffer, size_t elements, size_t size, Z_ARI_FILE *file) {
    return file->fread(buffer, elements, size);
}

size_t z_ari_fwrite(const void *buffer, size_t elements, size_t size, Z_ARI_FILE *file) {
    return file->fwrite(buffer, elements, size);
}



