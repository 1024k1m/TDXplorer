#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "np_loader.h"
#include "defs.h"

void print_consts(P_SEAMLDR_CONSTS_t * pseamldr_consts){

    LOG("CDataStackSize\t\t: 0x%lx\n", (ulong)pseamldr_consts->CDataStackSize);
    LOG("CCodeRgnSize\t\t: 0x%lx\n", (ulong)pseamldr_consts->CCodeRgnSize);
    LOG("CDataRgnSize\t\t: 0x%lx\n", (ulong)pseamldr_consts->CDataRgnSize);
    LOG("CKeyholeRgnSize\t\t: 0x%lx\n", (ulong)pseamldr_consts->CKeyholeRgnSize);
    LOG("CKeyholeEditRgnSize\t: 0x%lx\n", (ulong)pseamldr_consts->CKeyholeEditRgnSize);
    LOG("CEntryPointOffset\t: 0x%lx\n", (ulong)pseamldr_consts->CEntryPointOffset);
}

int get_pseamldr_consts(P_SEAMLDR_CONSTS_t * pseamldr_consts){

    int fd = open("data/pseamldr/pseamldr.so.consts", O_RDONLY);
    if(fd == -1)
    {
        LOG("unable to open pseamldr.so.consts\n");
        return -1;
    }
    if(read(fd, (void *)pseamldr_consts, sizeof(P_SEAMLDR_CONSTS_t)) == -1)
    {
        LOG("pseamldr.so.consts is empty\n");
        goto exit;
    }

    print_consts(pseamldr_consts);
    if(close(fd) == -1){
        LOG("unable to close pseamldr.so.consts\n");
        return -1;
    }
    return 0;

exit:
    if(close(fd) == -1){
        LOG("unable to close pseamldr.so.consts\n");
    }
    return -1;

}

ulong load_p_seamldr_code(){

    ulong size;
    int fd = open("data/pseamldr/pseamldr.so", O_RDONLY);
    if(fd == -1)
    {
        LOG("unable to open pseamldr.so\n");
        return -1;
    }
    
    size = lseek(fd, 0UL, SEEK_END);
    LOG("pseamldr.so size : 0x%lx\n", size);
    if((size == 0) || (SeamldrData.PSeamldrConsts->CCodeRgnSize < size)){
        LOG("invalid pseamldr.so size\n");
        goto exit;
    }
    if(lseek(fd, 0UL, SEEK_SET) != 0){
        LOG("lseek SEEK_SET failed\n");
        goto exit;
    }

    if(read(fd, (void *)(SeamldrData.SeamrrVaLimit - (SeamldrData.PSeamldrConsts->CCodeRgnSize + C_P_SYS_INFO_TABLE_SIZE)), size) != size){
        LOG("pseamldr.so read error\n");
        goto exit;
    }
    if(close(fd) == -1){
        LOG("unable to close pseamldr.so\n");
    }
    return size;

exit:
    if(close(fd) == -1){
        LOG("unable to close pseamldr.so\n");
    }
    return -1;

}

