//
//  misc.c
//  libhooker
//
//  Created by CoolStar on 2/24/20.
//  Copyright © 2020 CoolStar. All rights reserved.
//

#include "libhooker.h"
#include "funcMacros.h"

// 返回当前引擎版本，便于核对隔离测试与安装包。
LIBHOOKER_EXPORT const char *LHVersion(void){
#ifdef LH_ROOTHIDE
    return "libhooker 1.6.9-23+roothide (experimental). Copyright (C) 2022, CoolStar. All Rights Reserved.";
#else
    return "libhooker 1.7.0. Copyright (C) 2022, CoolStar. All Rights Reserved.";
#endif
}

// 将公开错误码转换为稳定的说明文本。
LIBHOOKER_EXPORT const char *LHStrError(enum LIBHOOKER_ERR err){
    switch (err) {
        case LIBHOOKER_OK:
            return "No Error";
            break;
        case LIBHOOKER_ERR_SELECTOR_NOT_FOUND:
            return "ObjC Selector Not Found";
        case LIBHOOKER_ERR_SHORT_FUNC:
            return "Function too short";
        case LIBHOOKER_ERR_BAD_INSN_AT_START:
            return "Bad instruction at function start";
        case LIBHOOKER_ERR_VM:
            return "Virtual Memory Error";
        case LIBHOOKER_ERR_NO_SYMBOL:
            return "No symbol was specified for hooking";
        case LIBHOOKER_ERR_ROLLBACK:
            return "Memory rollback failed; patches may remain active";
        default:
            return "Unknown Error";
            break;
    }
}
