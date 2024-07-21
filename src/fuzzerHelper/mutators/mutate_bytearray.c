#include "mutators.h"
#include "mutate_type.h"

MUTATE_TYPE(bytearray)
{
    MUTATE_TYPE_LOOP
    {
        
    }
    MERGE_STMT
    return STATE_OK;
}