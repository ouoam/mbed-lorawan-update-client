/**
 * 
 * ARTHUR M
 * 
 */

#ifndef _Z_ARI_FILE
#define _Z_ARI_FILE

#include "FragmentationBlockDeviceWrapper.h"
#include "Decompressor.h"

class Z_ARI_FILE {
public:
    /**
     * Constructor, creates a decompressed aritmetic file
     * offers classic FILE interface, with some restrictions.
     * 
     */
    Z_ARI_FILE(FragmentationBlockDeviceWrapper* _bd, size_t _offset, size_t _size);

    /**
     * Destructor, frees buffer memory
     * 
     */
    ~Z_ARI_FILE();

    /**
     * Offsets the uncompressed stream
     * @param pos the offset to consider
     * @param origin the reference point
     * Note : Only allows for Positive offset from current SEEK_CUR pos
     * @return 0 if success or -1 if failed
     */
    int fseek(long int pos, int origin);

    /**
     * Reads bytes from the decompressed stream
     * @param out ptr to buffer output
     * @param elements nb of elements to fetch
     * @param element_size size of elements to fetch
     * Note : reads elements*elements_size bytes 
     */
    size_t fread(void *out, size_t elements, size_t element_size);

    /**
     * NOT IMPLEMENTED
     */
    size_t fwrite(const void *buffer, size_t elements, size_t size);

    /**
     * Returns the position in the uncompressed file
     */
    long int ftell();


private:

    void _init_decompressor_stream(void);

    ArithmeticState_t arithmeticState;
    FragmentationBlockDeviceWrapper* bd;    //the bd instance wrapped (access to read/programm)
    uint8_t * buffer_z_file;    //buffer to store the file from bd
    size_t offset;      //address of the file in the bd 
    size_t size_z;      //size of the file on the bd
    size_t size_unz;    //size of the uncompressed file
    //int current_pos_z;  //position of the file read 
    int current_pos_unz;//position of the file uncompressed
};


// Functions similar to the POSIX functions

int z_ari_fseek(Z_ARI_FILE *file, long int pos, int origin);
long int z_ari_ftell(Z_ARI_FILE *file);
size_t z_ari_fread(void *buffer, size_t elements, size_t size, Z_ARI_FILE *file);
size_t z_ari_fwrite(const void *buffer, size_t elements, size_t size, Z_ARI_FILE *file);





#endif //_Z_ARI_FILE


