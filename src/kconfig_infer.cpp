#include "kconfig_infer.hpp"

#include <algorithm>
#include <string_view>
#include <vector>

#include "kconfig.hpp"  // kconfig_enabled_options

namespace ft {

namespace {

// Knowledge for one CONFIG option that the kernel-CVE table gates on:
//   syms    — built-in function symbols unique to the subsystem (kallsyms oracle)
//   modules — module base names (a .ko file or modules.builtin entry)
//   strings — distinctive image strings (rule-in only, weak)
//   builtin_only — the subsystem can never be a module, so a complete kallsyms
//                  without its symbols is a definitive rule-out on its own.
struct OptKnow {
    const char* opt;
    std::vector<const char*> syms;
    std::vector<const char*> modules;
    std::vector<const char*> strings;
    bool builtin_only;
};

const std::vector<OptKnow>& knowledge() {
    static const std::vector<OptKnow> k = {
        {"CONFIG_NETFILTER", {"nf_hook_slow", "nf_register_net_hook", "nf_register_hook"},
         {"x_tables", "nf_conntrack"}, {}, false},
        {"CONFIG_NF_TABLES", {"nft_do_chain", "nft_register_obj", "nf_tables_api_init"},
         {"nf_tables"}, {}, false},
        {"CONFIG_BPF_SYSCALL", {"bpf_prog_load", "bpf_check", "__sys_bpf"}, {}, {}, true},
        {"CONFIG_BPF_UNPRIV_DEFAULT_OFF", {}, {}, {}, false},  // sysctl default, config-only
        {"CONFIG_NET_CLS_ROUTE4", {"route4_classify"}, {"cls_route"}, {}, false},
        {"CONFIG_NET_CLS_TCINDEX", {"tcindex_classify"}, {"cls_tcindex"}, {}, false},
        {"CONFIG_NET_CLS_U32", {"u32_classify"}, {"cls_u32"}, {}, false},
        {"CONFIG_IO_URING", {"io_submit_sqes", "io_uring_create", "__do_sys_io_uring_setup"}, {},
         {"io_uring"}, true},
        {"CONFIG_UNIX", {"unix_create", "unix_stream_connect", "unix_dgram_recvmsg"}, {"unix"}, {},
         false},
        {"CONFIG_PACKET", {"packet_rcv", "tpacket_rcv", "packet_create"}, {"af_packet"}, {}, false},
        {"CONFIG_USER_NS", {"create_user_ns", "free_user_ns"}, {}, {}, true},
        {"CONFIG_CGROUPS", {"cgroup_attach_task", "cgroup_mkdir", "cgroup_procs_write"}, {}, {},
         true},
        {"CONFIG_OVERLAY_FS", {"ovl_fill_super", "ovl_lookup"}, {"overlay"}, {"overlayfs"}, false},
        {"CONFIG_FUSE_FS", {"fuse_fill_super", "fuse_dev_read", "fuse_request_alloc"}, {"fuse"}, {},
         false},
        {"CONFIG_ANDROID_BINDER_IPC", {"binder_ioctl", "binder_thread_read"},
         {"binder", "binder_linux"}, {}, false},
        {"CONFIG_IP_DCCP", {"dccp_v4_init_sock", "dccp_rcv_state_process"},
         {"dccp", "dccp_ipv4", "dccp_ipv6"}, {}, false},
        {"CONFIG_VSOCKETS", {"__vsock_create", "vsock_bind"}, {"vsock"}, {}, false},
        {"CONFIG_POSIX_MQUEUE", {"mqueue_get_inode", "mqueue_evict_inode"}, {}, {}, true},
        {"CONFIG_INET_ESP", {"esp_init_state", "esp6_init_state", "esp_output"}, {"esp4", "esp6"},
         {}, false},
        {"CONFIG_OPENVSWITCH", {"ovs_dp_process_packet", "ovs_vport_receive"}, {"openvswitch"}, {},
         false},
        {"CONFIG_TIPC", {"tipc_sk_create", "tipc_rcv"}, {"tipc"}, {}, false},
        {"CONFIG_MAC80211", {"ieee80211_register_hw", "ieee80211_rx_list"}, {"mac80211"}, {}, false},
        {"CONFIG_BT", {"hci_register_dev", "l2cap_recv_frame"}, {"bluetooth"}, {}, false},
        {"CONFIG_QAT", {"adf_dev_init", "qat_algs_register"},
         {"intel_qat", "qat_c62x", "qat_4xxx", "qat_dh895xcc"}, {}, false},
        {"CONFIG_SCSI_ISCSI_ATTRS", {"iscsi_create_session", "iscsi_add_session"},
         {"scsi_transport_iscsi"}, {}, false},
        {"CONFIG_KEYS", {"key_alloc", "keyring_alloc"}, {}, {}, true},
        {"CONFIG_PERF_EVENTS", {"perf_event_alloc", "perf_event_create_kernel_counter"}, {}, {},
         true},
    };
    return k;
}

const OptKnow* find_opt(const std::string& opt) {
    for (const auto& k : knowledge())
        if (opt == k.opt) return &k;
    return nullptr;
}

void mark_enabled(KernelConfigView& v, const std::string& opt, const char* src) {
    v.enabled.insert(opt);
    // First source to prove it wins the evidence label (sources are applied in
    // descending trust: config, modules.builtin, ko, kallsyms, strings).
    v.evidence.emplace(opt, src);
}

}  // namespace

bool looks_like_kconfig(std::span<const uint8_t> data) {
    if (data.size() < 128) return false;
    std::string_view head(reinterpret_cast<const char*>(data.data()),
                          std::min<size_t>(data.size(), 8192));
    // The generated-config banner is definitive.
    if (head.find("Automatically generated file") != std::string_view::npos &&
        head.find("Kernel Configuration") != std::string_view::npos)
        return true;
    // Header-less fallback (a stripped or dumped config). Require the "=y/=m" and
    // "# CONFIG_x is not set" idioms at real density AND kernel-only marker
    // options. The markers are the point: they reject buildroot / OpenWrt /
    // BusyBox `.config` files, which are just as CONFIG_-dense but describe
    // package selections, not the kernel — treating one as an authoritative
    // kernel config would falsely rule every subsystem out.
    std::string_view sv(reinterpret_cast<const char*>(data.data()), data.size());
    size_t on = 0, off = 0, from = 0;
    while ((from = sv.find("\nCONFIG_", from)) != std::string_view::npos) {
        ++on;
        from += 8;
        if (on > 40) break;
    }
    from = 0;
    while ((from = sv.find("\n# CONFIG_", from)) != std::string_view::npos) {
        ++off;
        from += 10;
        if (off > 10) break;
    }
    if (on <= 40 || off <= 10) return false;
    static const char* kmarkers[] = {"CONFIG_HZ", "CONFIG_MMU", "CONFIG_ARCH_",
                                     "CONFIG_INIT_ENV", "CONFIG_CC_IS_", "CONFIG_HAVE_ARCH_",
                                     "CONFIG_PAGE_OFFSET", "CONFIG_KALLSYMS"};
    int hits = 0;
    for (const char* m : kmarkers)
        if (sv.find(m) != std::string_view::npos) ++hits;
    return hits >= 2;
}

void infer_from_kconfig_text(const std::string& cfg, KernelConfigView& view) {
    view.authoritative = true;
    auto en = kconfig_enabled_options(cfg);  // CONFIG_X=y / =m
    for (auto& o : en) {
        view.enabled.insert(o);
        view.evidence.emplace(o, "kconfig");
    }
}

void infer_from_modules_builtin(std::span<const uint8_t> data, KernelConfigView& view) {
    view.modules_seen = true;
    std::string_view sv(reinterpret_cast<const char*>(data.data()), data.size());
    // Lines look like: kernel/net/netfilter/nf_tables.ko
    size_t start = 0;
    while (start <= sv.size()) {
        size_t nl = sv.find('\n', start);
        std::string_view line = sv.substr(start, nl == std::string_view::npos ? sv.size() - start
                                                                              : nl - start);
        size_t slash = line.rfind('/');
        std::string_view base = (slash == std::string_view::npos) ? line : line.substr(slash + 1);
        if (base.size() > 3 && base.substr(base.size() - 3) == ".ko") {
            std::string mod(base.substr(0, base.size() - 3));
            for (const auto& k : knowledge())
                for (const char* m : k.modules)
                    if (mod == m) {
                        view.modules_present.insert(k.opt);
                        mark_enabled(view, k.opt, "modules.builtin");
                    }
        }
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
}

void infer_from_ko_path(const std::string& relpath, KernelConfigView& view) {
    // Only count paths under a modules tree so unrelated *.ko don't mislead.
    if (relpath.find("lib/modules/") == std::string::npos) return;
    view.modules_seen = true;
    size_t slash = relpath.rfind('/');
    std::string base = (slash == std::string::npos) ? relpath : relpath.substr(slash + 1);
    if (base.size() <= 3 || base.substr(base.size() - 3) != ".ko") return;
    std::string mod = base.substr(0, base.size() - 3);
    // Some builds rename dashes to underscores; normalize.
    std::replace(mod.begin(), mod.end(), '-', '_');
    for (const auto& k : knowledge())
        for (const char* m : k.modules) {
            std::string mm(m);
            std::replace(mm.begin(), mm.end(), '-', '_');
            if (mod == mm) {
                view.modules_present.insert(k.opt);
                mark_enabled(view, k.opt, "ko-file");
            }
        }
}

void infer_from_kallsyms(const Kallsyms& ks, KernelConfigView& view) {
    if (ks.complete) view.kallsyms_complete = true;
    for (const auto& k : knowledge()) {
        if (k.syms.empty()) continue;
        bool any = false;
        for (const char* s : k.syms)
            if (ks.has(s)) { any = true; break; }
        if (any)
            mark_enabled(view, k.opt, "kallsyms");
        else if (ks.complete)
            view.not_builtin.insert(k.opt);
    }
}

void infer_from_kernel_strings(std::span<const uint8_t> data, KernelConfigView& view) {
    if (data.empty()) return;
    std::string_view hay(reinterpret_cast<const char*>(data.data()), data.size());
    for (const auto& k : knowledge()) {
        if (view.enabled.count(k.opt)) continue;  // already proven
        for (const char* s : k.strings)
            if (hay.find(s) != std::string_view::npos) {
                mark_enabled(view, k.opt, "string");
                break;
            }
    }
}

namespace {
int trust_rank(const std::string& src) {
    if (src == "kconfig") return 5;
    if (src == "modules.builtin") return 4;
    if (src == "ko-file") return 3;
    if (src == "kallsyms") return 2;
    if (src == "string") return 1;
    return 0;
}
}  // namespace

std::vector<HardeningItem> kernel_hardening(const std::string& cfg) {
    // Each feature with its CONFIG aliases (newest first). Aliases cover kernel
    // renames — e.g. the stack protector was CONFIG_CC_STACKPROTECTOR* before
    // ~4.18, CONFIG_STACKPROTECTOR* after; strict RWX was CONFIG_DEBUG_RODATA
    // before CONFIG_STRICT_KERNEL_RWX. A feature absent from the config entirely
    // (predates the kernel, or was trimmed) is Absent, not a finding.
    struct H {
        const char* name;
        std::vector<const char*> aliases;
    };
    static const std::vector<H> tab = {
        {"stack protector",
         {"CONFIG_STACKPROTECTOR_STRONG", "CONFIG_STACKPROTECTOR",
          "CONFIG_CC_STACKPROTECTOR_STRONG", "CONFIG_CC_STACKPROTECTOR_REGULAR",
          "CONFIG_CC_STACKPROTECTOR"}},
        {"fortify source", {"CONFIG_FORTIFY_SOURCE"}},
        {"kaslr", {"CONFIG_RANDOMIZE_BASE"}},
        {"strict kernel rwx", {"CONFIG_STRICT_KERNEL_RWX", "CONFIG_DEBUG_RODATA"}},
        {"hardened usercopy", {"CONFIG_HARDENED_USERCOPY"}},
        {"slab freelist hardened", {"CONFIG_SLAB_FREELIST_HARDENED"}},
        {"unprivileged bpf off", {"CONFIG_BPF_UNPRIV_DEFAULT_OFF"}},
        {"module signing", {"CONFIG_MODULE_SIG"}},
    };
    std::vector<HardeningItem> out;
    if (cfg.empty()) return out;
    std::string hay = "\n" + cfg;  // anchor line starts
    for (const auto& h : tab) {
        HardState st = HardState::Absent;
        for (const char* a : h.aliases) {
            std::string base = std::string("\n") + a;
            if (hay.find(base + "=y") != std::string::npos ||
                hay.find(base + "=m") != std::string::npos) {
                st = HardState::On;
                break;  // an enabled alias wins outright
            }
            if (st == HardState::Absent &&
                hay.find("\n# " + std::string(a) + " is not set") != std::string::npos)
                st = HardState::Off;  // available but disabled; keep looking for an On alias
        }
        out.push_back({h.name, st});
    }
    return out;
}

std::vector<std::string> gating_options() {
    std::vector<std::string> out;
    for (const auto& k : knowledge())
        if (!k.syms.empty() || !k.modules.empty() || !k.strings.empty())  // skip config-only pseudo opts
            out.push_back(k.opt);
    return out;
}

void merge_view(KernelConfigView& dst, const KernelConfigView& src) {
    dst.authoritative |= src.authoritative;
    dst.kallsyms_complete |= src.kallsyms_complete;
    dst.modules_seen |= src.modules_seen;
    dst.enabled.insert(src.enabled.begin(), src.enabled.end());
    dst.modules_present.insert(src.modules_present.begin(), src.modules_present.end());
    dst.not_builtin.insert(src.not_builtin.begin(), src.not_builtin.end());
    for (const auto& [opt, ev] : src.evidence) {
        auto it = dst.evidence.find(opt);
        if (it == dst.evidence.end() || trust_rank(ev) > trust_rank(it->second))
            dst.evidence[opt] = ev;
    }
}

KcveState config_option_state(const KernelConfigView& view, const std::string& opt,
                              std::string& evidence) {
    if (view.enabled.count(opt)) {
        auto it = view.evidence.find(opt);
        evidence = it != view.evidence.end() ? it->second : "present";
        return KcveState::Applicable;  // On
    }
    // Authoritative .config: anything not enabled is off.
    if (view.authoritative) {
        evidence = "kconfig";
        return KcveState::RuledOut;  // Off
    }
    // Complete kallsyms with the symbol absent: definitive for builtin-only
    // subsystems, or for modular ones we could also exclude via the modules tree.
    if (view.not_builtin.count(opt)) {
        const OptKnow* k = find_opt(opt);
        bool builtin_only = k && k->builtin_only;
        bool module_excluded = view.modules_seen && !view.modules_present.count(opt);
        if (builtin_only) {
            evidence = "kallsyms";
            return KcveState::RuledOut;
        }
        if (module_excluded) {
            evidence = "kallsyms+modules";
            return KcveState::RuledOut;
        }
    }
    evidence.clear();
    return KcveState::Unknown;
}

}  // namespace ft
