#pragma once
#include "ccglobal/export.h"

#if USE_LM_DB_DLL
    #define LM_DB_API CC_DECLARE_IMPORT
#elif USE_LM_DB_STATIC
    #define LM_DB_API CC_DECLARE_STATIC
#else
    #if LM_DB_DLL
        #define LM_DB_API CC_DECLARE_EXPORT
    #else
        #define LM_DB_API CC_DECLARE_STATIC
    #endif
#endif