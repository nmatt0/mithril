// kconfig_infer.hpp — recover kernel-config knowledge without an embedded
// .config, so the curated kernel-CVE checklist can still gate subsystems.
//
// A vendor kernel usually ships without CONFIG_IKCONFIG, so kconfig.cpp finds
// nothing and every in-range kernel CVE degrades to "config unknown". This
// module fills that gap from whatever the image does carry, in descending order
// of trust:
//   1. a real .config on the rootfs (/boot/config-*, a dumped /proc/config.gz):
//      authoritative — options are enabled or explicitly not-set.
//   2. /lib/modules/<ver>/modules.builtin and loadable .ko files: which modules
//      are built in (=y) or shipped as modules (=m).
//   3. the decoded kallsyms table (kallsyms.hpp): built-in symbols prove a
//      subsystem is compiled in; on a complete table their absence rules it out.
//   4. distinctive strings in the kernel image: weak, rule-in only.
// Each source contributes to a KernelConfigView; config_option_state() reads the
// merged view back as On / Off / Unknown with the evidence that decided it.
#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "kallsyms.hpp"
#include "kernelcve.hpp"

namespace ft {

// Does this file look like a kernel .config? (IKCONFIG header or a high density
// of CONFIG_ lines.) Cheap check before parsing.
bool looks_like_kconfig(std::span<const uint8_t> data);

// Source 1: a real .config text. authoritative — sets view.authoritative.
void infer_from_kconfig_text(const std::string& cfg, KernelConfigView& view);

// Source 2a: /lib/modules/<ver>/modules.builtin (newline-separated .ko paths).
void infer_from_modules_builtin(std::span<const uint8_t> data, KernelConfigView& view);

// Source 2b: one loadable module path (…/lib/modules/<ver>/…/foo.ko). Marks the
// mapped option present and records that modules were seen.
void infer_from_ko_path(const std::string& relpath, KernelConfigView& view);

// Source 3: a decoded kallsyms table. Built-in symbols -> enabled; on a complete
// table, options whose builtin symbols are all absent -> not_builtin.
void infer_from_kallsyms(const Kallsyms& ks, KernelConfigView& view);

// Source 4: distinctive strings in a kernel image (rule-in only, low trust).
void infer_from_kernel_strings(std::span<const uint8_t> data, KernelConfigView& view);

// Read the merged view for one option. `evidence` is set to the source label.
KcveState config_option_state(const KernelConfigView& view, const std::string& opt,
                              std::string& evidence);

// Merge a per-file view into an accumulator (union of evidence; the
// highest-trust source wins each option's label). Used to combine the config
// knowledge contributed by different files in a tree.
void merge_view(KernelConfigView& dst, const KernelConfigView& src);

// The CONFIG options the kernel-CVE checklist gates on (the knowledge-table
// names), for emitting the per-option evidence view. Sysctl-default pseudo
// options with no detectable evidence are omitted.
std::vector<std::string> gating_options();

// Kernel self-protection ("hardening") posture, read from a recovered .config.
// Tri-state per feature, because "off" and "the option did not exist in this
// kernel version" are different facts and only the former is a finding.
enum class HardState { On, Off, Absent };
struct HardeningItem {
    const char* name;   // friendly display name
    HardState state;
};
// Evaluate the known hardening features against a verbatim .config text (checks
// each feature's CONFIG aliases across kernel versions). Empty when no text.
std::vector<HardeningItem> kernel_hardening(const std::string& config_text);

}  // namespace ft
