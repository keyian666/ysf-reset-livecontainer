// YSFDeviceReset —— 云闪付 (com.unionpay.chsp) 设备身份重置
// 目标: iOS 15.x + TrollStore / LiveContainer
//
// v5 关键修复:
//   自检发现「系统类钩子全部命中, 云闪付自己的类全部 0 命中」。
//   原因是 LiveContainer 的 TweakLoader 先加载 tweak、后 dlopen 目标 App,
//   构造函数执行时云闪付的类还没注册, 全类扫描自然一无所获。
//
//   本版把 App 专属钩子(银联 HKE / 越狱检测 / 签名痕迹)延迟到
//   UIApplicationMain 入口执行 —— 此刻类已注册, 而 didFinishLaunching 尚未开始。
//   做法: 用 fishhook 一并拦 UIApplicationMain。
//
//   构造函数阶段仍会尝试一次(对 TrollFools 那条路径有效), 两次结果都写进自检文件。
//
// 另: 自检里增加 dlsym 直读的真实 hw.machine, 用于判定设备真身。
//
// 纯 Objective-C, 零 Logos 指令, 不依赖 CydiaSubstrate / ElleKit。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>

#pragma mark - ========== 伪装画像配置 ==========

#define YSF_FAKE_MACHINE   "iPhone10,1"                    // iPhone 8
#define YSF_FAKE_MODEL     "D20AP"
#define YSF_FAKE_MEMSIZE   (2ULL * 1024 * 1024 * 1024)

#pragma mark - ========== 锚点 ==========

static NSString *YSFAnchorPath(void) {
    static NSString *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *base = docs.count ? docs[0] : NSTemporaryDirectory();
        p = [base stringByAppendingPathComponent:@".ysf_anchor"];
    });
    return p;
}

static NSString *YSFAnchor(void) {
    static NSString *anchor = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *path = YSFAnchorPath();
        NSString *s = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
        if (s.length == 36) {
            anchor = [s copy];
            return;
        }
        anchor = [[[NSUUID UUID] UUIDString] copy];
        [anchor writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    });
    return anchor;
}

static NSUUID *YSFDeriveUUID(const char *salt) {
    NSString *seed = [NSString stringWithFormat:@"%@|%s", YSFAnchor(), salt];
    NSData *data = [seed dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char d[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, d);

    unsigned char u[16];
    memcpy(u, d, 16);
    u[6] = (unsigned char)((u[6] & 0x0F) | 0x40);
    u[8] = (unsigned char)((u[8] & 0x3F) | 0x80);
    return [[NSUUID alloc] initWithUUIDBytes:u];
}

static inline NSString *YSFDeriveUUIDString(const char *salt) {
    return [YSFDeriveUUID(salt) UUIDString];
}

static double YSFDeriveFraction(const char *salt) {
    NSString *seed = [NSString stringWithFormat:@"%@|frac|%s", YSFAnchor(), salt];
    NSData *data = [seed dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char d[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, d);
    unsigned int v = 0;
    memcpy(&v, d, sizeof(v));
    return (double)(v % 1000000u) / 1000000.0;
}

#pragma mark - ========== 自检输出 ==========

static NSString *YSFStatusPath(void) {
    return [[YSFAnchorPath() stringByDeletingLastPathComponent]
            stringByAppendingPathComponent:@".ysf_status.txt"];
}

static void YSFAppendStatus(NSString *text) {
    NSString *path = YSFStatusPath();
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[text dataUsingEncoding:NSUTF8StringEncoding]];
    } @finally {
        [fh closeFile];
    }
}

static NSString *YSFReadSysctlString(int (*fn)(const char *, void *, size_t *, void *, size_t),
                                     const char *key) {
    if (!fn) return @"空指针";
    char buf[256] = {0};
    size_t len = sizeof(buf);
    if (fn(key, buf, &len, NULL, 0) != 0) return @"读取失败";
    return [NSString stringWithUTF8String:buf] ?: @"解码失败";
}

static unsigned long long YSFReadSysctlU64(int (*fn)(const char *, void *, size_t *, void *, size_t),
                                           const char *key) {
    if (!fn) return 0;
    unsigned long long v = 0;
    size_t len = sizeof(v);
    if (fn(key, &v, &len, NULL, 0) != 0) return 0;
    return v;
}

#pragma mark - ========== Keychain / 缓存清理 ==========

static void YSFPurgeKeychain(void) {
    NSArray *classes = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity,
    ];

    for (id cls in classes) {
        CFTypeRef found = NULL;
        NSDictionary *query = @{
            (__bridge id)kSecClass:            cls,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
        };
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, &found);
        if (st != errSecSuccess || found == NULL) continue;

        NSArray *items = (__bridge_transfer NSArray *)found;
        for (NSDictionary *attr in items) {
            if (![attr isKindOfClass:[NSDictionary class]]) continue;

            NSMutableDictionary *del = [@{(__bridge id)kSecClass: cls} mutableCopy];
            NSArray *idKeys = @[
                (__bridge id)kSecAttrService,
                (__bridge id)kSecAttrAccount,
                (__bridge id)kSecAttrAccessGroup,
                (__bridge id)kSecAttrGeneric,
                (__bridge id)kSecAttrApplicationTag,
                (__bridge id)kSecAttrServer,
                (__bridge id)kSecAttrProtocol,
            ];
            for (NSString *k in idKeys) {
                if (attr[k]) del[k] = attr[k];
            }
            if (del.count <= 1) continue;
            SecItemDelete((__bridge CFDictionaryRef)del);
        }
    }
}

static BOOL YSFKeyLooksLikeIdentity(NSString *key) {
    static NSArray<NSString *> *needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[ @"device", @"uuid", @"idfa", @"idfv", @"smid", @"sm_id",
                     @"smdevice", @"jcore", @"jpush", @"regrandom", @"bootuuid",
                     @"udid", @"nas", @"imei", @"fingerprint", @"token" ];
    });
    NSString *lk = key.lowercaseString;
    for (NSString *n in needles) {
        if ([lk containsString:n]) return YES;
    }
    return NO;
}

static void YSFPurgeDefaults(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];
    for (NSString *k in all.allKeys) {
        if (YSFKeyLooksLikeIdentity(k)) [ud removeObjectForKey:k];
    }
    [ud synchronize];

    NSArray *suites = @[ @"com.unionpay.chsp", @"com.ishumei.antifraud",
                         @"cn.jpush", @"com.unionpay" ];
    for (NSString *s in suites) {
        NSUserDefaults *sud = [[NSUserDefaults alloc] initWithSuiteName:s];
        if (!sud) continue;
        NSDictionary *d = [sud dictionaryRepresentation];
        for (NSString *k in d.allKeys) {
            if (YSFKeyLooksLikeIdentity(k)) [sud removeObjectForKey:k];
        }
        [sud synchronize];
    }
}

static void YSFPurgeCaches(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *libs = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    if (!libs.count) return;
    NSString *lib = libs[0];
    for (NSString *sub in @[ @"Caches", @"Preferences", @"WebKit", @"HTTPStorages" ]) {
        NSString *p = [lib stringByAppendingPathComponent:sub];
        if ([fm fileExistsAtPath:p]) {
            [fm removeItemAtPath:p error:NULL];
        }
    }
}

#pragma mark - ========== fishhook (精简版) ==========

struct YSF_Rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct YSF_RebindEntry {
    struct YSF_Rebinding *items;
    size_t count;
    struct YSF_RebindEntry *next;
};

static struct YSF_RebindEntry *YSF_entries = NULL;

static void YSF_append_entry(struct YSF_RebindEntry *e) {
    e->next = YSF_entries;
    YSF_entries = e;
}

static void YSF_rebind_section(const struct section_64 *sec,
                               intptr_t slide,
                               const struct nlist_64 *symtab,
                               const char *strtab,
                               const uint32_t *indirect) {
    if (!sec->size) return;

    uint32_t count = (uint32_t)(sec->size / sizeof(void *));
    void **bindings = (void **)((uintptr_t)slide + (uintptr_t)sec->addr);
    if (!bindings) return;

    for (uint32_t j = 0; j < count; j++) {
        uint32_t idx = indirect[sec->reserved1 + j];
        if (idx == INDIRECT_SYMBOL_LOCAL || idx == INDIRECT_SYMBOL_ABS) continue;
        if (idx == (uint32_t)-1) continue;

        const char *sym = strtab + symtab[idx].n_un.n_strx;
        if (!sym || !*sym) continue;
        if (sym[0] == '_') sym++;

        for (struct YSF_RebindEntry *e = YSF_entries; e; e = e->next) {
            for (size_t i = 0; i < e->count; i++) {
                if (strcmp(sym, e->items[i].name) != 0) continue;

                void *orig = bindings[j];
                if (!orig) continue;
                if (e->items[i].replaced && *(e->items[i].replaced) == NULL) {
                    *(e->items[i].replaced) = orig;
                }

                vm_address_t page = (vm_address_t)((uintptr_t)&bindings[j] &
                                                   ~(uintptr_t)(getpagesize() - 1));
                vm_size_t len = (vm_size_t)getpagesize() * 2;
                vm_protect(mach_task_self(), page, len, false,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                bindings[j] = e->items[i].replacement;
                vm_protect(mach_task_self(), page, len, false, VM_PROT_READ);
            }
        }
    }
}

static void YSF_rebind_image(const struct mach_header_64 *mh, intptr_t slide) {
    if (!mh) return;

    const struct segment_command_64 *linkedit = NULL;
    const struct segment_command_64 *segs[2] = { NULL, NULL };
    const struct symtab_command *symtabCmd = NULL;
    const struct dysymtab_command *dysymtabCmd = NULL;

    uintptr_t cursor = (uintptr_t)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize == 0) break;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
            if (strcmp(sc->segname, "__LINKEDIT") == 0)        linkedit = sc;
            else if (strcmp(sc->segname, "__DATA") == 0)       segs[0] = sc;
            else if (strcmp(sc->segname, "__DATA_CONST") == 0) segs[1] = sc;
        } else if (lc->cmd == LC_SYMTAB) {
            symtabCmd = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysymtabCmd = (const struct dysymtab_command *)lc;
        }
        cursor += lc->cmdsize;
    }

    if (!linkedit || !symtabCmd || !dysymtabCmd) return;

    uintptr_t linkedit_base = (uintptr_t)slide
                            + (uintptr_t)linkedit->vmaddr
                            - (uintptr_t)linkedit->fileoff;

    const struct nlist_64 *symtab = (const struct nlist_64 *)(linkedit_base + symtabCmd->symoff);
    const char *strtab = (const char *)(linkedit_base + symtabCmd->stroff);
    const uint32_t *indirect = (const uint32_t *)(linkedit_base + dysymtabCmd->indirectsymoff);
    if (!symtab || !strtab || !indirect) return;

    for (int s = 0; s < 2; s++) {
        const struct segment_command_64 *seg = segs[s];
        if (!seg) continue;

        const struct section_64 *sect = (const struct section_64 *)
            ((const char *)seg + sizeof(struct segment_command_64));
        for (uint32_t k = 0; k < seg->nsects; k++) {
            uint32_t type = sect[k].flags & SECTION_TYPE;
            if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) {
                YSF_rebind_section(&sect[k], slide, symtab, strtab, indirect);
            }
        }
    }
}

static void YSF_rebind_callback(const struct mach_header *mh, intptr_t slide) {
    if (!mh) return;
    if (mh->magic != MH_MAGIC_64) return;
    YSF_rebind_image((const struct mach_header_64 *)mh, slide);
}

static void YSF_rebind_all(void) {
    uint32_t total = _dyld_image_count();
    for (uint32_t i = 0; i < total; i++) {
        YSF_rebind_callback(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
    _dyld_register_func_for_add_image(YSF_rebind_callback);
}

#pragma mark - ========== 被拦截的 C 函数 ==========

static int (*YSF_orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*YSF_orig_UIApplicationMain)(int, char *[], NSString *, NSString *) = NULL;

static int YSF_fake_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                                 void *newp, size_t newlen) {
    if (name && newp == NULL) {
        const char *strval = NULL;
        char bootbuf[37] = {0};

        if (strcmp(name, "hw.machine") == 0) {
            strval = YSF_FAKE_MACHINE;
        } else if (strcmp(name, "hw.model") == 0) {
            strval = YSF_FAKE_MODEL;
        } else if (strcmp(name, "kern.bootsessionuuid") == 0) {
            static char cached[37] = {0};
            if (!cached[0]) {
                NSString *u = [[NSUUID UUID] UUIDString];
                memcpy(cached, u.UTF8String, sizeof(cached) - 1);
            }
            memcpy(bootbuf, cached, sizeof(bootbuf) - 1);
            strval = bootbuf;
        }

        if (strval) {
            size_t need = strlen(strval) + 1;
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp == NULL) return EINVAL;
            if (*oldlenp < need) {
                *oldlenp = need;
                return ENOMEM;
            }
            memcpy(oldp, strval, need);
            *oldlenp = need;
            return 0;
        }

        if (strcmp(name, "hw.memsize") == 0) {
            unsigned long long numval = YSF_FAKE_MEMSIZE;
            size_t need = sizeof(numval);
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp == NULL) return EINVAL;
            if (*oldlenp < need) {
                *oldlenp = need;
                return ENOMEM;
            }
            memcpy(oldp, &numval, need);
            *oldlenp = need;
            return 0;
        }
    }

    if (YSF_orig_sysctlbyname) {
        return YSF_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
    return ENOTSUP;
}

#pragma mark - ========== swizzle 工具 ==========

static Method YSFFindMethod(Class cls, SEL sel) {
    for (Class c = cls; c != Nil; c = class_getSuperclass(c)) {
        unsigned int n = 0;
        Method *ms = class_copyMethodList(c, &n);
        Method found = NULL;
        for (unsigned int i = 0; i < n; i++) {
            if (method_getName(ms[i]) == sel) { found = ms[i]; break; }
        }
        if (ms) free(ms);
        if (found) return found;
    }
    return NULL;
}

static BOOL YSFSwizzleClassSelObject(const char *clsName, const char *selCStr, id (^value)(void)) {
    Class cls = objc_getClass(clsName);
    if (!cls) return NO;
    Method m = YSFFindMethod(cls, sel_registerName(selCStr));
    if (!m) return NO;

    NSUInteger nargs = method_getNumberOfArguments(m) - 2;
    IMP imp = NULL;
    if (nargs == 0) {
        imp = imp_implementationWithBlock(^id(id s){ return value(); });
    } else if (nargs == 1) {
        imp = imp_implementationWithBlock(^id(id s, id a){ return value(); });
    } else if (nargs == 2) {
        imp = imp_implementationWithBlock(^id(id s, id a, id b){ return value(); });
    }
    if (!imp) return NO;
    method_setImplementation(m, imp);
    return YES;
}

static BOOL YSFSwizzleClassSelBool(const char *clsName, const char *selCStr, BOOL value) {
    Class cls = objc_getClass(clsName);
    if (!cls) return NO;
    Method m = YSFFindMethod(cls, sel_registerName(selCStr));
    if (!m) return NO;
    if (method_getNumberOfArguments(m) != 2) return NO;

    IMP imp = imp_implementationWithBlock(^BOOL(id s){ return value; });
    if (!imp) return NO;
    method_setImplementation(m, imp);
    return YES;
}

static BOOL YSFSwizzleClassSelU64(const char *clsName, const char *selCStr, unsigned long long value) {
    Class cls = objc_getClass(clsName);
    if (!cls) return NO;
    Method m = YSFFindMethod(cls, sel_registerName(selCStr));
    if (!m) return NO;
    if (method_getNumberOfArguments(m) != 2) return NO;

    IMP imp = imp_implementationWithBlock(^unsigned long long(id s){ return value; });
    if (!imp) return NO;
    method_setImplementation(m, imp);
    return YES;
}

static NSUInteger YSFSwizzleSelReturnObject(const char *selCStr, id (^value)(void)) {
    SEL sel = sel_registerName(selCStr);
    NSUInteger replaced = 0;
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return 0;

    for (unsigned int i = 0; i < count; i++) {
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(classes[i], &mcount);
        if (!methods) continue;

        for (unsigned int j = 0; j < mcount; j++) {
            if (method_getName(methods[j]) != sel) continue;

            NSUInteger nargs = method_getNumberOfArguments(methods[j]) - 2;
            IMP imp = NULL;
            if (nargs == 0) {
                imp = imp_implementationWithBlock(^id(id s){ return value(); });
            } else if (nargs == 1) {
                imp = imp_implementationWithBlock(^id(id s, id a){ return value(); });
            } else if (nargs == 2) {
                imp = imp_implementationWithBlock(^id(id s, id a, id b){ return value(); });
            } else if (nargs == 3) {
                imp = imp_implementationWithBlock(^id(id s, id a, id b, id c){ return value(); });
            }
            if (imp) {
                method_setImplementation(methods[j], imp);
                replaced++;
            }
        }
        free(methods);
    }
    free(classes);
    return replaced;
}

static NSUInteger YSFSwizzleSelReturnNO(const char *selCStr) {
    SEL sel = sel_registerName(selCStr);
    NSUInteger replaced = 0;
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return 0;

    for (unsigned int i = 0; i < count; i++) {
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(classes[i], &mcount);
        if (!methods) continue;

        for (unsigned int j = 0; j < mcount; j++) {
            if (method_getName(methods[j]) != sel) continue;

            NSUInteger nargs = method_getNumberOfArguments(methods[j]) - 2;
            IMP imp = NULL;
            if (nargs == 0) {
                imp = imp_implementationWithBlock(^BOOL(id s){ return NO; });
            } else if (nargs == 1) {
                imp = imp_implementationWithBlock(^BOOL(id s, id a){ return NO; });
            } else if (nargs == 2) {
                imp = imp_implementationWithBlock(^BOOL(id s, id a, id b){ return NO; });
            }
            if (imp) {
                method_setImplementation(methods[j], imp);
                replaced++;
            }
        }
        free(methods);
    }
    free(classes);
    return replaced;
}

#pragma mark - ========== App 专属钩子 (必须等目标类加载完) ==========

// 只在云闪付的类都已注册之后才有意义。
// 构造函数阶段调用一次(对 TrollFools 路径有效),
// UIApplicationMain 入口再调用一次(LiveContainer 路径下这时才真的能命中)。
static void YSFInstallAppHooks(const char *phase) {
    @autoreleasepool {
        NSMutableString *log = [NSMutableString string];
        [log appendFormat:@"\n--- App 钩子安装阶段: %s ---\n", phase];

        NSUInteger c1 = YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV8StrongWithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8-strong");
        });
        NSUInteger c2 = YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV8WeakWithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8-weak");
        });
        NSUInteger c3 = YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV8WithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8");
        });
        NSUInteger c4 = YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV7WithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v7");
        });
        [log appendFormat:@"  银联 V8Strong/V8Weak/V8/V7 : %lu / %lu / %lu / %lu\n",
            (unsigned long)c1, (unsigned long)c2, (unsigned long)c3, (unsigned long)c4];

        static const char *noSels[] = {
            "isJailBreak", "hasJailbreakFile", "hasMobileSubstrate", "isRooted",
            "p_isJailBreak1", "p_isJailBreak2", "isJailBreakWithPtrace:",
            "hasCydia", "isDeviceJailbreak", "checkJailBreak",
        };
        NSUInteger total = 0;
        for (size_t i = 0; i < sizeof(noSels) / sizeof(noSels[0]); i++) {
            NSUInteger n = YSFSwizzleSelReturnNO(noSels[i]);
            total += n;
            if (n > 0) {
                [log appendFormat:@"    %-24s : %lu\n", noSels[i], (unsigned long)n];
            }
        }
        [log appendFormat:@"  越狱检测合计 : %lu\n", (unsigned long)total];

        NSUInteger cAuth = YSFSwizzleSelReturnObject("authorityWithJailBreakFlag:", ^{
            return (id)nil;
        });
        [log appendFormat:@"  authorityWithJailBreakFlag: : %lu\n", (unsigned long)cAuth];

        YSFAppendStatus(log);
    }
}

static int YSF_fake_UIApplicationMain(int argc, char *argv[],
                                      NSString *principalClassName,
                                      NSString *delegateClassName) {
    // 此刻目标 App 的类已全部注册, 而 didFinishLaunching 尚未开始
    YSFInstallAppHooks("UIApplicationMain");

    if (YSF_orig_UIApplicationMain) {
        return YSF_orig_UIApplicationMain(argc, argv, principalClassName, delegateClassName);
    }
    return 0;
}

#pragma mark - ========== 启动逻辑 ==========

__attribute__((constructor, used))
static void YSFDeviceResetInit(void) {
    @autoreleasepool {
        NSMutableString *log = [NSMutableString string];

        NSString *anchorPath = YSFAnchorPath();
        NSString *rerollPath = [[anchorPath stringByDeletingLastPathComponent]
                                stringByAppendingPathComponent:@".ysf_reroll"];
        NSFileManager *fm = [NSFileManager defaultManager];

        BOOL fresh  = ![fm fileExistsAtPath:anchorPath];
        BOOL reroll = [fm fileExistsAtPath:rerollPath];

        [log appendFormat:@"=== YSFDeviceReset v5 自检 ===\n"];
        [log appendFormat:@"时间     : %@\n", [NSDate date]];
        [log appendFormat:@"首次运行 : %@    重滚标记 : %@\n", fresh ? @"是" : @"否", reroll ? @"是" : @"否"];

        if (fresh || reroll) {
            YSFPurgeKeychain();
            YSFPurgeDefaults();
            YSFPurgeCaches();
            (void)YSFAnchor();
            if (reroll) [fm removeItemAtPath:rerollPath error:NULL];
            [log appendString:@"清理动作 : 已执行 Keychain / NSUserDefaults / 缓存\n"];
        } else {
            [log appendString:@"清理动作 : 锚点已存在, 跳过(身份保持稳定)\n"];
        }

        [log appendFormat:@"锚点     : %@\n", YSFAnchor()];
        [log appendFormat:@"派生 IDFV: %@\n", YSFDeriveUUIDString("idfv")];
        [log appendFormat:@"派生 IDFA: %@\n", YSFDeriveUUIDString("idfa")];

        // ---- fishhook: sysctlbyname + UIApplicationMain ----
        struct YSF_RebindEntry *e = (struct YSF_RebindEntry *)malloc(sizeof(struct YSF_RebindEntry));
        if (e) {
            e->items = (struct YSF_Rebinding *)malloc(sizeof(struct YSF_Rebinding) * 2);
            if (e->items) {
                e->items[0].name        = "sysctlbyname";
                e->items[0].replacement = (void *)YSF_fake_sysctlbyname;
                e->items[0].replaced    = (void **)&YSF_orig_sysctlbyname;

                e->items[1].name        = "UIApplicationMain";
                e->items[1].replacement = (void *)YSF_fake_UIApplicationMain;
                e->items[1].replaced    = (void **)&YSF_orig_UIApplicationMain;

                e->count = 2;
                YSF_append_entry(e);
                YSF_rebind_all();
            } else {
                free(e);
            }
        }

        [log appendFormat:@"\n[sysctl] 重绑: %@\n",
            YSF_orig_sysctlbyname ? @"成功" : @"失败(未找到符号)"];
        [log appendFormat:@"  hw.machine 经我们钩子 = %@\n",
            YSFReadSysctlString(YSF_fake_sysctlbyname, "hw.machine")];
        [log appendFormat:@"  hw.machine 经捕获的原始指针 = %@\n",
            YSFReadSysctlString(YSF_orig_sysctlbyname, "hw.machine")];

        // dlsym 直接取符号, 绕过一切 GOT 重绑 —— 这是设备真身的唯一可信读数
        {
            int (*real)(const char *, void *, size_t *, void *, size_t) =
                (int (*)(const char *, void *, size_t *, void *, size_t))
                    dlsym(RTLD_DEFAULT, "sysctlbyname");
            [log appendFormat:@"  hw.machine 经 dlsym 直读 = %@   <-- 设备真身\n",
                YSFReadSysctlString(real, "hw.machine")];
            [log appendFormat:@"  hw.memsize 经 dlsym 直读 = %llu\n",
                YSFReadSysctlU64(real, "hw.memsize")];
            [log appendFormat:@"  UIApplicationMain 重绑: %@\n",
                YSF_orig_UIApplicationMain ? @"成功" : @"失败(未找到符号)"];
        }

        // ---- 系统类: 任何时刻都在, 构造函数阶段直接装 ----
        BOOL okIDFV = YSFSwizzleClassSelObject("UIDevice", "identifierForVendor", ^{
            return (id)YSFDeriveUUID("idfv");
        });
        BOOL okIDFA = YSFSwizzleClassSelObject("ASIdentifierManager", "advertisingIdentifier", ^{
            return (id)YSFDeriveUUID("idfa");
        });
        BOOL okAttr = YSFSwizzleClassSelBool("ASIdentifierManager",
                                             "isAdvertisingTrackingEnabled", YES);
        BOOL okMem  = YSFSwizzleClassSelU64("NSProcessInfo", "physicalMemory",
                                            (unsigned long long)YSF_FAKE_MEMSIZE);
        BOOL okDisk = YSFSwizzleClassSelObject("NSFileManager",
                                               "attributesOfFileSystemForPath:error:", ^{
            double f = YSFDeriveFraction("disk");
            unsigned long long total = 64ULL * 1000 * 1000 * 1000;
            if (f > 0.66)      total = 256ULL * 1000 * 1000 * 1000;
            else if (f > 0.33) total = 128ULL * 1000 * 1000 * 1000;
            unsigned long long freeBytes =
                (unsigned long long)((double)total * (0.25 + YSFDeriveFraction("diskfree") * 0.5));
            return (id)@{
                NSFileSystemSize:     @(total),
                NSFileSystemFreeSize: @(freeBytes),
            };
        });

        [log appendString:@"\n[系统类]\n"];
        [log appendFormat:@"  UIDevice.identifierForVendor                : %@\n", okIDFV ? @"OK" : @"未找到"];
        [log appendFormat:@"  ASIdentifierManager.advertisingIdentifier   : %@\n", okIDFA ? @"OK" : @"未找到"];
        [log appendFormat:@"  ASIdentifierManager.isAdvertisingTracking... : %@\n", okAttr ? @"OK" : @"未找到"];
        [log appendFormat:@"  NSProcessInfo.physicalMemory                : %@\n", okMem ? @"OK" : @"未找到"];
        [log appendFormat:@"  NSFileManager.attributesOfFileSystem...     : %@\n", okDisk ? @"OK" : @"未找到"];

        // 覆盖写: 新一轮自检从头开始
        [log writeToFile:YSFStatusPath()
              atomically:YES
                encoding:NSUTF8StringEncoding
                   error:NULL];

        // 构造函数阶段先试一次 App 钩子(结果追加到文件)
        YSFInstallAppHooks("constructor");
    }
}
