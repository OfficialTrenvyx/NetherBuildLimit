#include <jni.h>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstring>
#include <vector>
#include <sys/stat.h>
#include <sys/mman.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>

#define TAG "NetherBuildLimit"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static const char* LOG_PATH = "/storage/emulated/0/games/NetherBuildLimit/logs/mod.log";

static void ensure_log_dir() {
    mkdir("/storage/emulated/0/games/NetherBuildLimit",       0777);
    mkdir("/storage/emulated/0/games/NetherBuildLimit/logs/", 0777);
}

static void write_log(const std::string& msg) {
    std::ofstream f(LOG_PATH, std::ios::app);
    if (!f.is_open()) return;
    time_t now = time(nullptr);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    f << "[" << ts << "] " << msg << "\n";
    f.flush();
    LOGI("%s", msg.c_str());
}

static inline int32_t pack_range(int16_t max, int16_t min) {
    return ((int32_t)max << 16) | (uint16_t)min;
}

static inline void unpack_range(int32_t v, int16_t& out_max, int16_t& out_min) {
    out_max = (int16_t)(v >> 16);
    out_min = (int16_t)(v & 0xFFFF);
}

// ── Trampoline ───────────────────────────────────────────────────────────────
// We save the first 16 bytes (4 instructions) of the target function,
// then write an absolute jump to our hook. The trampoline lets us call
// the original function after patching.

static uint8_t  trampoline[32];   // saved instructions + jump back
static bool     hook_installed = false;

// Absolute jump sequence for AArch64 (16 bytes):
// LDR X17, #8        ; load address from next 8 bytes
// BR  X17            ; branch to it
// <8-byte address>
static void write_abs_jump(uint8_t* dst, uintptr_t target_addr) {
    uint32_t ldr = 0x58000051; // LDR X17, #8
    uint32_t br  = 0xD61F0220; // BR X17
    memcpy(dst + 0, &ldr, 4);
    memcpy(dst + 4, &br,  4);
    memcpy(dst + 8, &target_addr, 8);
}

static bool make_writable(uintptr_t addr, size_t size) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t aligned = addr & ~(page - 1);
    return mprotect(reinterpret_cast<void*>(aligned), size + page,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static bool make_rx(uintptr_t addr, size_t size) {
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t aligned = addr & ~(page - 1);
    return mprotect(reinterpret_cast<void*>(aligned), size + page,
                    PROT_READ | PROT_EXEC) == 0;
}

// ── Hook callback ────────────────────────────────────────────────────────────

using OrigFn = int64_t(*)(void*, void*,
    void*, void*, void*, void*, void*, void*,
    void*, void*, void*, void*, void*, void*,
    void*, void*, void*, void*, void*, void*);

static OrigFn call_original = nullptr;

static int64_t hooked_fn(void* a, void* b,
    void* c1,  void* c2,  void* c3,  void* c4,
    void* c5,  void* c6,  void* c7,  void* c8,
    void* c9,  void* c10, void* c11, void* c12,
    void* c13, void* c14, void* c15, void* c16,
    void* c17, void* c18)
{
    if (b) {
        int32_t* range_ptr = reinterpret_cast<int32_t*>(
            reinterpret_cast<uint8_t*>(b) + 0x64);

        char name_buf[16] = {};
        memcpy(name_buf,
               reinterpret_cast<const uint8_t*>(range_ptr) + 4, 15);

        char clean[16] = {};
        int ci = 0;
        for (int i = 0; i < 15 && name_buf[i] != '\0'; i++) {
            if ((unsigned char)name_buf[i] >= 32)
                clean[ci++] = name_buf[i];
        }

        if (strcmp(clean, "Nether") == 0) {
            int16_t cur_max, cur_min;
            unpack_range(*range_ptr, cur_max, cur_min);
            if (cur_max != 256) {
                *range_ptr = pack_range(256, cur_min);
                std::ostringstream oss;
                oss << "Nether build limit: " << cur_max << " -> 256";
                write_log(oss.str());
            }
        }
    }
    return call_original(a, b, c1, c2, c3, c4, c5, c6, c7, c8,
                         c9, c10, c11, c12, c13, c14, c15, c16, c17, c18);
}

// ── Install hook ─────────────────────────────────────────────────────────────

static bool install_hook(uintptr_t fn_addr) {
    if (hook_installed) return true;

    // Save original 16 bytes into trampoline
    memcpy(trampoline, reinterpret_cast<void*>(fn_addr), 16);

    // Write jump back (after the 16 saved bytes) to fn_addr+16
    write_abs_jump(trampoline + 16, fn_addr + 16);

    // Make trampoline executable
    if (!make_writable(reinterpret_cast<uintptr_t>(trampoline), 32)) {
        write_log("mprotect trampoline failed");
        return false;
    }
    make_rx(reinterpret_cast<uintptr_t>(trampoline), 32);
    __builtin___clear_cache(
        reinterpret_cast<char*>(trampoline),
        reinterpret_cast<char*>(trampoline + 32));

    call_original = reinterpret_cast<OrigFn>(trampoline);

    // Patch target function: write jump to hooked_fn
    if (!make_writable(fn_addr, 16)) {
        write_log("mprotect target failed");
        return false;
    }

    write_abs_jump(reinterpret_cast<uint8_t*>(fn_addr),
                   reinterpret_cast<uintptr_t>(hooked_fn));

    __builtin___clear_cache(
        reinterpret_cast<char*>(fn_addr),
        reinterpret_cast<char*>(fn_addr + 16));

    make_rx(fn_addr, 16);

    hook_installed = true;
    write_log("Hook installed via inline patch");
    return true;
}

// ── Scanner ──────────────────────────────────────────────────────────────────

struct TextRange { uintptr_t start; size_t size; };

static TextRange get_text_section() {
    TextRange result = {0, 0};
    void* handle = dlopen("libminecraftpe.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) { write_log("dlopen failed"); return result; }

    struct Ctx { void* handle; uintptr_t start; size_t size; };
    Ctx ctx = { handle, 0, 0 };

    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) -> int {
        auto* ctx = reinterpret_cast<Ctx*>(data);
        if (!info->dlpi_name) return 0;
        void* h = dlopen(info->dlpi_name, RTLD_LAZY | RTLD_NOLOAD);
        if (!h || h != ctx->handle) { if (h) dlclose(h); return 0; }
        dlclose(h);
        for (int i = 0; i < info->dlpi_phnum; i++) {
            auto& ph = info->dlpi_phdr[i];
            if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
                ctx->start = info->dlpi_addr + ph.p_vaddr;
                ctx->size  = ph.p_memsz;
                break;
            }
        }
        return 1;
    }, &ctx);

    dlclose(handle);
    result.start = ctx.start;
    result.size  = ctx.size;
    return result;
}

static uintptr_t find_target_function() {
    TextRange text = get_text_section();
    if (!text.start || !text.size) {
        write_log("Failed to get .text section");
        return 0;
    }
    write_log("Scanning .text section...");

    const uint32_t* code = reinterpret_cast<const uint32_t*>(text.start);
    size_t count = text.size / 4;

    bool seen_ret       = false;
    uintptr_t last_pos  = 0;
    uintptr_t cap_addr  = 0;
    size_t closest_dist = SIZE_MAX;
    std::vector<uintptr_t> fn_starts;

    for (size_t i = 0; i < count; i++) {
        uint32_t instr = code[i];
        uintptr_t addr = text.start + i * 4;

        if ((instr & 0xFFFFFC1F) == 0xD65F0000) {
            seen_ret = true;
        } else if (seen_ret && (instr & 0xFF000000) == 0xD1000000) {
            fn_starts.push_back(addr);
            seen_ret = false;
        } else {
            uint32_t masked = instr & 0xFFFFFFE0;
            if (masked != 0x52A84200 && masked != 0xF2E84200) continue;
            if (last_pos) {
                size_t dist = addr - last_pos;
                if (dist < closest_dist) {
                    closest_dist = dist;
                    cap_addr = addr;
                }
            }
            last_pos = addr;
        }
    }

    if (!cap_addr) { write_log("Pattern not found"); return 0; }

    uintptr_t best = 0;
    for (uintptr_t s : fn_starts)
        if (s < cap_addr && s > best) best = s;

    if (!best) { write_log("Function start not found"); return 0; }

    std::ostringstream oss;
    oss << "Target function at 0x" << std::hex << best;
    write_log(oss.str());
    return best;
}

// ── Entry points ─────────────────────────────────────────────────────────────

static void do_init() {
    ensure_log_dir();
    write_log("NetherBuildLimit loading...");

    uintptr_t fn_addr = find_target_function();
    if (!fn_addr) {
        write_log("FAILED: target function not found");
        return;
    }

    if (!install_hook(fn_addr)) {
        write_log("FAILED: hook installation failed");
        return;
    }

    write_log("Done!");
}

extern "C" __attribute__((constructor))
void lib_constructor() { do_init(); }

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM*, void*) {
    do_init();
    return JNI_VERSION_1_6;
}

extern "C"
void mod_init() { do_init(); }

