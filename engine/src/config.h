#ifndef CONFIG_H_
#define CONFIG_H_

#if CARD == 1060
    #define BLOCK_SIZE 256
    #define MAX_THREADS_PER_SM 2048
    #define SM_COUNT 9
#elif CARD == 1650
    #define BLOCK_SIZE 256
    #define MAX_THREADS_PER_SM 1024
    #define SM_COUNT 14
#elif CARD == 5060
    #define BLOCK_SIZE 256
    #define MAX_THREADS_PER_SM 1536
    #define SM_COUNT 36
#elif CARD == 3050
    #define BLOCK_SIZE 256
    #define MAX_THREADS_PER_SM 1536
    #define SM_COUNT 20
#else
    #error "Invalid CARD value"
#endif

#define BLOCKS_PER_SM (MAX_THREADS_PER_SM / BLOCK_SIZE)
#define GRID_SIZE (BLOCKS_PER_SM * SM_COUNT)
#define TOTAL_THREADS (GRID_SIZE * BLOCK_SIZE)

#ifdef TOTAL_THREADS
# define NTHREADS TOTAL_THREADS
#else
# define NTHREADS (gridDim.x * blockDim.x)
#endif

#define TID (blockDim.x * blockIdx.x + threadIdx.x)

#endif // CONFIG_H_
