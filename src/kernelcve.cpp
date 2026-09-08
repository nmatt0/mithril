#include "kernelcve.hpp"

#include "kconfig_infer.hpp"
#include "version.hpp"

namespace ft {

namespace {

// One curated entry. `introduced`/`fixed` are mainline versions ("" = open end).
// `req` = CONFIG options the subsystem needs (all must be enabled to be
// reachable); `mit` = options that mitigate it (any enabled -> ruled out).
struct KCve {
    const char* cve;
    const char* introduced;
    const char* fixed;
    const char* impact;
    std::vector<const char*> req;
    std::vector<const char*> mit;
    const char* note;
};

const std::vector<KCve>& table() {
    static const std::vector<KCve> t = {
        // --- core mm / fs / ptrace: always compiled in (no CONFIG gate) ---
        {"CVE-2016-5195", "2.6.22", "4.8.3", "LPE", {}, {}, "Dirty COW: COW race in core mm; universal, public exploits."},
        {"CVE-2022-0847", "5.8", "5.16.11", "LPE", {}, {}, "Dirty Pipe: pipe page-cache overwrite; trivial public exploit."},
        {"CVE-2021-33909", "", "5.13.4", "LPE", {}, {}, "Sequoia: seq_file size_t underflow; public exploit."},
        {"CVE-2019-13272", "", "5.1.17", "LPE", {}, {}, "ptrace PTRACE_TRACEME parent cred handling; public exploit."},
        {"CVE-2018-14634", "", "4.18.9", "LPE", {}, {}, "Mutagen Astronomy: create_elf_tables int overflow (64-bit, large argv)."},
        {"CVE-2023-3269", "6.1", "6.4.1", "LPE", {}, {}, "StackRot: maple-tree stack expansion UAF."},
        {"CVE-2016-0728", "", "4.4.1", "LPE", {"CONFIG_KEYS"}, {}, "keyring refcount overflow."},
        {"CVE-2014-3153", "", "3.15", "LPE", {}, {}, "futex requeue (TowelRoot); ubiquitous Android/old-kernel root."},
        {"CVE-2017-5123", "", "4.13.5", "LPE", {}, {}, "waitid() missing access_ok (no SMAP); public exploit."},
        {"CVE-2021-3347", "", "5.11", "LPE", {}, {}, "PI-futex UAF; local root."},
        {"CVE-2013-2094", "", "3.8.9", "LPE", {"CONFIG_PERF_EVENTS"}, {}, "perf_event_open type confusion; classic public exploit."},
        {"CVE-2017-1000112", "", "4.13", "LPE", {}, {}, "UFO/UDP fragmentation OOB write (chocobo_root); public exploit."},

        // --- netfilter / nftables (CONFIG_NF_TABLES / CONFIG_NETFILTER) ---
        {"CVE-2021-22555", "2.6.19", "5.12", "LPE", {"CONFIG_NETFILTER"}, {}, "x_tables OOB write; widely-used public exploit."},
        {"CVE-2023-32233", "", "6.4", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables anonymous-set UAF; unpriv path needs CONFIG_USER_NS."},
        {"CVE-2022-32250", "", "5.18.1", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables set UAF; public exploit."},
        {"CVE-2022-34918", "", "5.18.9", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables nft_set_elem type confusion."},
        {"CVE-2022-2586", "", "5.19", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables cross-table set UAF."},
        {"CVE-2023-35001", "", "6.4.3", "LPE", {"CONFIG_NF_TABLES"}, {}, "nft_byteorder OOB (Pwn2Own)."},
        {"CVE-2024-1086", "", "6.8", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables nft_verdict double-free; public exploit, widely used."},
        {"CVE-2022-1015", "5.5", "5.17", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables register OOB (Bouman); public exploit."},
        {"CVE-2024-1085", "", "6.8", "LPE", {"CONFIG_NF_TABLES"}, {}, "nf_tables anonymous-set double-free (sibling of 2024-1086)."},
        {"CVE-2023-0179", "", "6.2", "LPE", {"CONFIG_NF_TABLES"}, {}, "nft_payload stack OOB leak -> LPE; public PoC."},

        // --- eBPF (CONFIG_BPF_SYSCALL; unpriv-bpf mitigation) ---
        {"CVE-2021-3490", "5.7", "5.13", "LPE", {"CONFIG_BPF_SYSCALL"}, {"CONFIG_BPF_UNPRIV_DEFAULT_OFF"}, "eBPF ALU32 bounds; public exploit."},
        {"CVE-2017-16995", "4.4", "4.14.8", "LPE", {"CONFIG_BPF_SYSCALL"}, {"CONFIG_BPF_UNPRIV_DEFAULT_OFF"}, "eBPF verifier sign-extension; public exploit."},
        {"CVE-2020-8835", "5.5", "5.6.1", "LPE", {"CONFIG_BPF_SYSCALL"}, {"CONFIG_BPF_UNPRIV_DEFAULT_OFF"}, "eBPF 32-bit bounds tracking; Pwn2Own."},

        // --- traffic control / net scheduler ---
        {"CVE-2022-2588", "", "5.19", "LPE", {"CONFIG_NET_CLS_ROUTE4"}, {}, "cls_route filter UAF; public exploit."},
        {"CVE-2023-1829", "", "6.3", "LPE", {"CONFIG_NET_CLS_TCINDEX"}, {}, "tcindex UAF."},
        {"CVE-2022-29581", "", "5.17", "LPE", {"CONFIG_NET_CLS_U32"}, {}, "cls_u32 refcount UAF; public exploit."},

        // --- io_uring (CONFIG_IO_URING) ---
        {"CVE-2021-41073", "5.11", "5.14.6", "LPE", {"CONFIG_IO_URING"}, {}, "io_uring loop_rw_iter type confusion."},
        {"CVE-2022-1786", "5.11", "5.18", "LPE", {"CONFIG_IO_URING"}, {}, "io_uring UAF."},
        {"CVE-2023-2598", "6.3", "6.4", "LPE", {"CONFIG_IO_URING"}, {}, "io_uring fixed-buffer OOB (Pwn2Own)."},
        {"CVE-2022-2602", "", "6.0", "LPE", {"CONFIG_IO_URING", "CONFIG_UNIX"}, {}, "io_uring/af_unix GC UAF; public exploit."},

        // --- af_packet (CONFIG_PACKET) ---
        {"CVE-2016-8655", "", "4.9", "LPE", {"CONFIG_PACKET"}, {}, "af_packet PACKET_TX_RING race; public exploit."},
        {"CVE-2017-7308", "", "4.10.6", "LPE", {"CONFIG_PACKET"}, {}, "af_packet ring-buffer OOB; public exploit."},
        {"CVE-2020-14386", "", "5.9", "LPE", {"CONFIG_PACKET"}, {}, "af_packet tpacket_rcv OOB write."},
        {"CVE-2021-22600", "", "5.16", "LPE", {"CONFIG_PACKET"}, {}, "af_packet packet_set_ring double-free; public exploit."},

        // --- filesystems / namespaces (containers) ---
        {"CVE-2022-0185", "", "5.16.2", "LPE", {"CONFIG_USER_NS"}, {}, "fs_context legacy-param heap overflow; container escape."},
        {"CVE-2021-4154", "", "5.16", "LPE", {"CONFIG_CGROUPS"}, {}, "cgroup-v1 fs_context UAF."},
        {"CVE-2023-0386", "", "6.2", "LPE", {"CONFIG_OVERLAY_FS", "CONFIG_FUSE_FS"}, {}, "OverlayFS FUSE setuid copy-up; public exploit."},
        {"CVE-2015-1328", "", "4.1", "LPE", {"CONFIG_OVERLAY_FS"}, {}, "overlayfs permission bypass (Ubuntu); classic LPE."},

        // --- android (CONFIG_ANDROID_BINDER_IPC) ---
        {"CVE-2019-2215", "", "5.0", "LPE", {"CONFIG_ANDROID_BINDER_IPC"}, {}, "Binder use-after-free (used in the wild, NSO); Android LPE."},

        // --- transports / protocols ---
        {"CVE-2017-6074", "", "4.9.11", "LPE", {"CONFIG_IP_DCCP"}, {}, "DCCP double-free UAF; public exploit."},
        {"CVE-2015-3636", "", "4.1", "LPE", {}, {}, "ping-socket UAF (PingPongRoot); Android root where ping_group_range permits."},
        {"CVE-2021-26708", "", "5.10.13", "LPE", {"CONFIG_VSOCKETS"}, {}, "AF_VSOCK multi-transport race; public exploit."},
        {"CVE-2017-11176", "", "4.11.9", "LPE", {"CONFIG_POSIX_MQUEUE"}, {}, "mq_notify netlink UAF; public exploit."},
        {"CVE-2022-27666", "", "5.17", "LPE", {"CONFIG_INET_ESP"}, {}, "esp6 IPsec buffer overflow."},
        {"CVE-2022-2639", "", "6.0", "LPE", {"CONFIG_OPENVSWITCH"}, {}, "openvswitch reserve_sfa_size OOB."},

        // --- remote (RCE) ---
        {"CVE-2021-43267", "5.10", "5.15.1", "RCE", {"CONFIG_TIPC"}, {}, "TIPC MSG_CRYPTO heap overflow; remote if TIPC exposed."},
        {"CVE-2022-0435", "", "5.17", "RCE", {"CONFIG_TIPC"}, {}, "TIPC monitoring stack overflow; remote/LPE."},
        {"CVE-2019-11477", "", "4.19.42", "DoS", {}, {}, "SACK Panic: TCP remote DoS (panic), no code-exec."},
        // Wireless (CONFIG_MAC80211): remotely triggerable over the air by a nearby AP/beacon.
        {"CVE-2022-42719", "5.1", "6.1", "RCE", {"CONFIG_MAC80211"}, {}, "mac80211 MBSSID element UAF; remote via crafted beacon."},
        {"CVE-2022-42720", "5.1", "6.1", "RCE", {"CONFIG_MAC80211"}, {}, "mac80211 BSS refcount UAF; remote (companion to 42719)."},
        // Bluetooth (CONFIG_BT): remote over BR/EDR (BleedingTooth); proximity RCE.
        {"CVE-2020-12351", "4.8", "5.10", "RCE", {"CONFIG_BT"}, {}, "BleedingTooth: L2CAP A2MP type confusion; remote BT RCE."},
        {"CVE-2024-24246", "", "6.7", "LPE", {"CONFIG_QAT"}, {}, "QAT driver UAF (hardware-specific)."},

        // --- misc high-signal ---
        {"CVE-2021-27365", "", "5.11.4", "LPE", {"CONFIG_SCSI_ISCSI_ATTRS"}, {}, "iSCSI netlink heap OOB."},
        {"CVE-2022-25636", "", "5.16.11", "LPE", {"CONFIG_NETFILTER"}, {}, "nf_dup_netdev / flowtable OOB write; public exploit."},
        // (Baron Samedit CVE-2021-3156 and pkexec CVE-2021-4034 are userland LPEs,
        // not kernel bugs; they belong to the secrets/binary passes, not here.)
    };
    return t;
}

bool version_affected(const std::string& v, const KCve& e) {
    if (e.introduced[0] && deb_vercmp(v, e.introduced) < 0) return false;
    if (e.fixed[0] && deb_vercmp(v, e.fixed) >= 0) return false;
    return true;
}

}  // namespace

std::vector<KernelCveResult> kernel_cve_scan(const std::string& kernel_version,
                                             const KernelConfigView* view) {
    std::vector<KernelCveResult> out;
    if (kernel_version.empty()) return out;
    const bool have_cfg = view && !view->empty();
    for (const auto& e : table()) {
        if (!version_affected(kernel_version, e)) continue;
        KernelCveResult r;
        r.cve = e.cve;
        r.impact = e.impact;
        r.note = e.note;
        if (!have_cfg) {
            r.state = KcveState::Unknown;
            r.applicable = false;
            r.reason = "config unknown (no kconfig recovered)";
            out.push_back(std::move(r));
            continue;
        }
        // Required options: any Off rules the CVE out; any Unknown (with no Off)
        // leaves it undetermined; all On means the subsystem is present.
        bool ruled = false, unknown = false;
        std::string ev;
        for (const char* rq : e.req) {
            std::string oe;
            KcveState st = config_option_state(*view, rq, oe);
            if (st == KcveState::RuledOut) {
                r.state = KcveState::RuledOut;
                r.reason = std::string("requires ") + rq + " (not enabled" +
                           (oe.empty() ? "" : ", " + oe) + ")";
                ruled = true;
                break;
            }
            if (st == KcveState::Unknown) { unknown = true; if (ev.empty()) ev = rq; }
        }
        if (!ruled) {
            // Mitigations: any known-enabled mitigation rules it out.
            for (const char* m : e.mit) {
                std::string oe;
                if (config_option_state(*view, m, oe) == KcveState::Applicable) {
                    r.state = KcveState::RuledOut;
                    r.reason = std::string("mitigated by ") + m;
                    ruled = true;
                    break;
                }
            }
        }
        if (!ruled) {
            if (unknown) {
                r.state = KcveState::Unknown;
                r.reason = ev.empty() ? "config undetermined" : (ev + " undetermined");
            } else {
                r.state = KcveState::Applicable;
                r.reason = "subsystem present";
            }
        }
        r.applicable = (r.state == KcveState::Applicable);
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<KernelCveResult> kernel_cve_scan(const std::string& kernel_version,
                                             const std::set<std::string>* enabled) {
    if (!enabled) return kernel_cve_scan(kernel_version, static_cast<const KernelConfigView*>(nullptr));
    KernelConfigView v;
    v.enabled = *enabled;
    v.authoritative = true;
    for (const auto& o : v.enabled) v.evidence.emplace(o, "kconfig");
    return kernel_cve_scan(kernel_version, &v);
}

}  // namespace ft
