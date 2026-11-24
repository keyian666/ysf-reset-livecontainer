// YSFDeviceReset —— 云闪付 (com.unionpay.chsp) 设备身份重置 / 指纹扩面版
// 目标: iOS 15.x + TrollStore / LiveContainer
//
// v4 修复: v3 用「全类扫描」替换了通用 selector(`name` / `hostName` /
//          `systemUptime`), 把 FrontBoardServices 等系统类的同名方法也一并
//          改掉, 导致它把设备名当成 XPC 服务名, 动态生成了
//            BSXPCServiceConnectionProxy<我的 iPhone>
//          然后调 handshakeWithRemnants: 抛 unrecognized selector 崩溃。
//
//          本版:
//            - 删除 UIDevice.name / NSProcessInfo.hostName / systemUptime
//              (前者是崩溃元凶, 后两者同类风险且收益低)
//            - 其余钩子改为「类限定」, 只在目标类上替换, 不再全扫
//            - 全类扫描仅保留真正唯一的 selector(银联 HKE / 越狱检测)
//
// 纯 Objective-C, 零 Logos 指令, 不依赖 CydiaSubstrate / ElleKit。
//
// 伪装画像: iPhone10,1 (iPhone 8)
//   4.7" 750x1334 @2x / Touch ID / 2GB / A11 —— 与 SE2 屏幕物理参数完全一致。

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
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>

#pragma mark - ========== 伪装画像配置 ==========

#define YSF_FAKE_MACHINE   "iPhone10,1"                    // iPhone 8
#define YSF_FAKE_MODEL     "D20AP"                         // iPhone10,1 主板代号
#define YSF_FAKE_MEMSIZE   (2ULL * 1024 * 1024 * 1024)     // 2GB

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

#pragma mark - ========== sysctlbyname 拦截 ==========

static int (*YSF_orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;

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

// 沿继承链查找方法, 但不跨类污染
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

// ---- 类限定: 只在指定类上替换, 绝不全扫 ----

static void YSFSwizzleClassSelObject(const char *clsName, const char *selCStr, id (^value)(void)) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;
    Method m = YSFFindMethod(cls, sel_registerName(selCStr));
    if (!m) return;

    NSUInteger nargs = method_getNumberOfArguments(m) - 2;
    IMP imp = NULL;
    if (nargs == 0) {
        imp = imp_implementationWithBlock(^id(id s){ return value(); });
    } else if (nargs == 1) {
        imp = imp_implementationWithBlock(^id(id s, id a){ return value(); });
    } else if (nargs == 2) {
        imp = imp_implementationWithBlock(^id(id s, id a, id b){ return value(); });
    }
    if (imp) method_setImplementation(m, imp);
}

static void YSFSwizzleClassSelBool(const char *clsName, const char *selCStr, BOOL value) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;
    Method m = YSFFindMethod(cls, sel_registerName(selCStr));
    if (!m) return;
    if (method_getNumberOfArguments(m) != 2) return;

    IMP imp = imp_implementationWithBlock(^BOOL(id s){ return value; });
    if (imp) method_setImplementation(m, imp);
}

static void YSFSwizzleClassSelU64(const char *clsName, const char *selCStr, unsigned long long value) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;
    Method m = YSFFindMethod(cls, sel_registerName(selCStr));
    if (!m) return;
    if (method_getNumberOfArguments(m) != 2) return;

    IMP imp = imp_implementationWithBlock(^unsigned long long(id s){ return value; });
    if (imp) method_setImplementation(m, imp);
}

// ---- 全局扫描: 仅用于名字独一无二的 selector(银联 HKE / 越狱检测) ----

static void YSFSwizzleSelReturnObject(const char *selCStr, id (^value)(void)) {
    SEL sel = sel_registerName(selCStr);
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return;

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
            if (imp) method_setImplementation(methods[j], imp);
        }
        free(methods);
    }
    free(classes);
}

static void YSFSwizzleSelReturnNO(const char *selCStr) {
    SEL sel = sel_registerName(selCStr);
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return;

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
            if (imp) method_setImplementation(methods[j], imp);
        }
        free(methods);
    }
    free(classes);
}

#pragma mark - ========== 启动逻辑 ==========

// constructor: dyld 加载时自动调用; used: 避免 -Werror 下的 -Wunused-function
__attribute__((constructor, used))
static void YSFDeviceResetInit(void) {
    @autoreleasepool {
        NSString *anchorPath = YSFAnchorPath();
        NSString *rerollPath = [[anchorPath stringByDeletingLastPathComponent]
                                stringByAppendingPathComponent:@".ysf_reroll"];
        NSFileManager *fm = [NSFileManager defaultManager];

        BOOL fresh  = ![fm fileExistsAtPath:anchorPath];
        BOOL reroll = [fm fileExistsAtPath:rerollPath];

        if (fresh || reroll) {
            YSFPurgeKeychain();
            YSFPurgeDefaults();
            YSFPurgeCaches();
            (void)YSFAnchor();
            if (reroll) [fm removeItemAtPath:rerollPath error:NULL];
        }

        // ---- libc: sysctlbyname (机型 / 主板 / 内存 / 启动会话 UUID) ----
        struct YSF_RebindEntry *e = (struct YSF_RebindEntry *)malloc(sizeof(struct YSF_RebindEntry));
        if (e) {
            e->items = (struct YSF_Rebinding *)malloc(sizeof(struct YSF_Rebinding));
            if (e->items) {
                e->items[0].name        = "sysctlbyname";
                e->items[0].replacement = (void *)YSF_fake_sysctlbyname;
                e->items[0].replaced    = (void **)&YSF_orig_sysctlbyname;
                e->count = 1;
                YSF_append_entry(e);
                YSF_rebind_all();
            } else {
                free(e);
            }
        }

        // ---- 原生标识: 全部类限定, 不碰系统类的同名方法 ----
        YSFSwizzleClassSelObject("UIDevice", "identifierForVendor", ^{
            return (id)YSFDeriveUUID("idfv");
        });
        YSFSwizzleClassSelObject("ASIdentifierManager", "advertisingIdentifier", ^{
            return (id)YSFDeriveUUID("idfa");
        });
        YSFSwizzleClassSelBool("ASIdentifierManager", "isAdvertisingTrackingEnabled", YES);
        YSFSwizzleClassSelU64("NSProcessInfo", "physicalMemory",
                              (unsigned long long)YSF_FAKE_MEMSIZE);

        // ---- 磁盘容量: 限定在 NSFileManager ----
        YSFSwizzleClassSelObject("NSFileManager", "attributesOfFileSystemForPath:error:", ^{
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

        // ---- 银联 ISOpenSDK 设备标识 (名字唯一, 可全扫) ----
        YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV8StrongWithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8-strong");
        });
        YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV8WeakWithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8-weak");
        });
        YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV8WithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v8");
        });
        YSFSwizzleSelReturnObject("GetHkeDeviceIdentifierV7WithArg:", ^{
            return (id)YSFDeriveUUIDString("hke-v7");
        });

        // ---- 越狱 / 签名痕迹 (名字唯一, 可全扫) ----
        static const char *noSels[] = {
            "isJailBreak", "hasJailbreakFile", "hasMobileSubstrate", "isRooted",
            "p_isJailBreak1", "p_isJailBreak2", "isJailBreakWithPtrace:",
            "hasCydia", "isDeviceJailbreak", "checkJailBreak",
        };
        for (size_t i = 0; i < sizeof(noSels) / sizeof(noSels[0]); i++) {
            YSFSwizzleSelReturnNO(noSels[i]);
        }

        YSFSwizzleSelReturnObject("authorityWithJailBreakFlag:", ^{
            return (id)nil;
        });
    }
}
