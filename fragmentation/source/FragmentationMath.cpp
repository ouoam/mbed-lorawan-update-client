/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
    (C)2017 Semtech

Description: 	Firmware update over the air with LoRa proof of concept
				Functions for the decoding
*/

#include "FragmentationMath.h"

#include "mbed_trace.h"
#define TRACE_GROUP "FMTH"

FragmentationMath::FragmentationMath(FragmentationBlockDeviceWrapper *flash, uint16_t frame_count, uint8_t frame_size, uint16_t redundancy_max, size_t flash_offset)
    : _flash(flash), _frame_count(frame_count), _frame_size(frame_size), _redundancy_max(redundancy_max), _flash_offset(flash_offset)
{
}

FragmentationMath::~FragmentationMath()
{
    if (matrixM2B)
    {
        free(matrixM2B);
    }
    if (missingFrameIndex)
    {
        free(missingFrameIndex);
    }
    if (matrixRow)
    {
        free(matrixRow);
    }
    if (matrixDataTemp)
    {
        free(matrixDataTemp);
    }
    if (dataTempVector)
    {
        free(dataTempVector);
    }
    if (dataTempVector2)
    {
        free(dataTempVector2);
    }
    if (s)
    {
        free(s);
    }
    if (xorRowDataTemp)
    {
        free(xorRowDataTemp);
    }
}

bool FragmentationMath::initialize()
{
    // global for this session
    matrixM2B = (uint8_t *)calloc(((_redundancy_max >> 3) + 1) * _redundancy_max, 1);

    missingFrameIndex = (uint16_t *)calloc(_frame_count, sizeof(uint16_t));

    // these get reset for every frame
    matrixRow = (bool *)calloc(_frame_count, 1);
    matrixDataTemp = (uint8_t *)calloc(_frame_size, 1);
    dataTempVector = (bool *)calloc(_redundancy_max, 1);
    dataTempVector2 = (bool *)calloc(_redundancy_max, 1);
    xorRowDataTemp = (uint8_t *)calloc(_frame_size, 1);
    s = (bool *)calloc(_redundancy_max, 1);

    numberOfLoosingFrame = 0;
    lastReceiveFrameCnt = 0;

    if (!matrixM2B ||
        !missingFrameIndex ||
        !matrixRow ||
        !matrixDataTemp ||
        !dataTempVector ||
        !dataTempVector2 ||
        !s ||
        !xorRowDataTemp)
    {
        tr_warn("Could not allocate memory");
        return false;
    }

    for (size_t ix = 0; ix < _frame_count; ix++)
    {
        missingFrameIndex[ix] = 1;
    }

    for (size_t ix = 0; ix < _redundancy_max; ix++)
    {
        s[ix] = 0;
    }

    for( uint32_t i = 0; i < ( ((_redundancy_max >> 3) + 1) * _redundancy_max ); i++ )
    {
       matrixM2B[i] = 0xFF;
    }

    return true;
}

void FragmentationMath::set_frame_found(uint16_t frameCounter)
{
    missingFrameIndex[frameCounter - 1] = 0;

    FindMissingReceiveFrame(frameCounter);
}

int FragmentationMath::process_redundant_frame(uint16_t frameCounter, uint8_t *rowData, FragmentationMathSessionParams_t sFotaParameter)
{
    static int m2l = 0;
    int haveMissingFrame = 0;
    int noInfo = 0;

    memset(matrixRow, 0, _frame_count);
    memset(matrixDataTemp, 0, _frame_size);
    memset(dataTempVector, 0, _redundancy_max);
    memset(dataTempVector2, 0, _redundancy_max);
    // we should not mess with rowData
    memcpy(xorRowDataTemp, rowData, sFotaParameter.DataSize);

    FindMissingReceiveFrame(frameCounter);

    FragmentationGetParityMatrixRow(frameCounter - sFotaParameter.NbOfFrag, sFotaParameter.NbOfFrag, matrixRow); //frameCounter-sFotaParameter.NbOfFrag

    for (int l = 0; l < sFotaParameter.NbOfFrag; l++) {
        if (matrixRow[l] == 1) {
            if (missingFrameIndex[l] == 0) { // xor with already receive frame
                GetRowInFlash(l, matrixDataTemp);
                XorLineData(xorRowDataTemp, matrixDataTemp, sFotaParameter.DataSize);
            } else { // fill the "little" boolean matrix m2b
                dataTempVector[missingFrameIndex[l] - 1] = 1;
                if (haveMissingFrame == 0) {
                    haveMissingFrame = 1;
                }
            }
        }
    }
    if (haveMissingFrame > 0)
    { //manage a new line in MatrixM2B
        int firstOneInRow = FindFirstOne(dataTempVector, numberOfLoosingFrame);
        while (s[firstOneInRow] == 1)
        { // row already diagonalized exist&(sFotaParameter.MatrixM2B[firstOneInRow][0])
            ExtractLineFromBinaryMatrix(dataTempVector2, firstOneInRow, numberOfLoosingFrame);
            XorLineBool(dataTempVector, dataTempVector2, numberOfLoosingFrame);
            int li = FindMissingFrameIndex(firstOneInRow); // have to store it in the mi th position of the missing frame
            GetRowInFlash(li, matrixDataTemp);
            XorLineData(xorRowDataTemp, matrixDataTemp, sFotaParameter.DataSize);
            if (VectorIsNull(dataTempVector, numberOfLoosingFrame))
            {
                noInfo = 1;
                break;
            }
            firstOneInRow = FindFirstOne(dataTempVector, numberOfLoosingFrame);
        }
        
        if (noInfo == 0)
        {
            PushLineToBinaryMatrix(dataTempVector, firstOneInRow, numberOfLoosingFrame);
            int li = FindMissingFrameIndex(firstOneInRow);
            StoreRowInFlash(xorRowDataTemp, li);
            s[firstOneInRow] = 1;
            m2l++;
        }

        if (m2l == numberOfLoosingFrame)
        { // then last step diagonalized
            if (numberOfLoosingFrame > 1)
            {
                for (int i = (numberOfLoosingFrame - 2); i >= 0; i--)
                {
                    int li = FindMissingFrameIndex(i);
                    GetRowInFlash(li, matrixDataTemp);
                    for (int j = (numberOfLoosingFrame - 1); j > i; j--)
                    {
                        ExtractLineFromBinaryMatrix(dataTempVector2, i, numberOfLoosingFrame);
                        ExtractLineFromBinaryMatrix(dataTempVector, j, numberOfLoosingFrame);
                        if (dataTempVector2[j] == 1)
                        {
                            XorLineBool(dataTempVector2, dataTempVector, numberOfLoosingFrame);
                            PushLineToBinaryMatrix(dataTempVector2, i, numberOfLoosingFrame);

                            int lj = FindMissingFrameIndex(j);

                            GetRowInFlash(lj, xorRowDataTemp);
                            XorLineData(matrixDataTemp, xorRowDataTemp, sFotaParameter.DataSize);
                        }
                    }
                    StoreRowInFlash(matrixDataTemp, li);
                }
                return numberOfLoosingFrame;
            } else { //ifnot ( numberOfLoosingFrame > 1 )
                return numberOfLoosingFrame; // 0 or 1
            }
        }
    }

    return FRAG_SESSION_ONGOING;
}

int FragmentationMath::get_lost_frame_count()
{
    return numberOfLoosingFrame;
}

void FragmentationMath::GetRowInFlash(int l, uint8_t *rowData)
{
    int r = _flash->read(rowData, _flash_offset + (l * _frame_size), _frame_size);
    if (r != 0) {
        tr_warn("GetRowInFlash for row %d failed (%d)", l, r);
    }
}

void FragmentationMath::StoreRowInFlash(uint8_t *rowData, int index)
{
    int r = _flash->program(rowData, _flash_offset + (_frame_size * index), _frame_size);
    if (r != 0) {
        tr_warn("StoreRowInFlash for row %d failed (%d)", index, r);
    }
}

uint16_t FragmentationMath::FindMissingFrameIndex(uint16_t x)
{
    for (uint16_t i = 0; i < _frame_count; i++) {
        if (missingFrameIndex[i] == (x + 1)) {
            return i;
        }
    }
    return 0;
}

void FragmentationMath::FindMissingReceiveFrame(uint16_t frameCounter)
{
    uint16_t q;

    for (q = lastReceiveFrameCnt; q < (frameCounter - 1); q++)
    {
        if (q < _frame_count)
        {
            numberOfLoosingFrame++;
            missingFrameIndex[q] = numberOfLoosingFrame;
        }
    }
    if (q < _frame_count)
    {
        lastReceiveFrameCnt = frameCounter;
    }
    else
    {
        lastReceiveFrameCnt = _frame_count + 1;
    }
}

void FragmentationMath::XorLineData(uint8_t *dataL1, uint8_t *dataL2, int size)
{
    for (int i = 0; i < size; i++) {
        dataL1[i] ^= dataL2[i];
    }
}

void FragmentationMath::XorLineBool(bool *dataL1, bool *dataL2, int size)
{
    for (int i = 0; i < size; i++) {
        dataL1[i] ^= dataL2[i];
    }
}

int FragmentationMath::FindFirstOne(bool *boolData, int size)
{
    for (int i = 0; i < size; i++) {
        if (boolData[i] == 1) {
            return i;
        }
    }
    return 0;
}

bool FragmentationMath::VectorIsNull(bool *boolData, int size)
{
    for (int i = 0; i < size; i++) {
        if (boolData[i] == 1) {
            return false;
        }
    }
    return true;
}

void FragmentationMath::ExtractLineFromBinaryMatrix(bool *boolVector, int rownumber, int numberOfBit)
{
    int findBit = rownumber * numberOfBit - ((rownumber * (rownumber - 1)) / 2);
    for (int i = 0; i < rownumber; i++) {
        boolVector[i] = 0;
    }
    for (int i = rownumber; i < numberOfBit; i++) {
        boolVector[i] = (matrixM2B[findBit >> 3] >> (7 - (findBit & 0x7))) & 0x01; // get bit
        findBit++;
    }
}

void FragmentationMath::PushLineToBinaryMatrix(bool *boolVector, int rownumber, int numberOfBit)
{
    int findBit = rownumber * numberOfBit - ((rownumber * (rownumber - 1)) / 2);

    for (int i = rownumber; i < numberOfBit; i++) {
        if (boolVector[i] == 0) {
            matrixM2B[findBit >> 3] &= ~(1 << (7 - (findBit & 0x7))); // clear bit
        }
        findBit++;
    }
}

void FragmentationMath::FragmentationGetParityMatrixRow(int N, int M, bool *matrixRow)
{
    memset(matrixRow, 0, M);

    int m = 0;
    if (IsPowerOfTwo(M)) {
        m = 1;
    }

    int x = 1 + (1001 * N);

    for (int nbCoeff = 0; nbCoeff < (M >> 1); nbCoeff++) {
        int r = 1 << 16;
        while (r >= M) {
            x = FragmentationPrbs23(x);
            r = x % (M + m);
        }
        matrixRow[r] = 1;
    }
}

int FragmentationMath::FragmentationPrbs23(int x)
{
    int b0 = x & 1;
    int b1 = (x & 0x20) >> 5;
    return (x >> 1) + ((b0 ^ b1) << 22);
}

bool FragmentationMath::IsPowerOfTwo(unsigned int x)
{
    return x != 0 && (x & (x-1)) == 0;
}
