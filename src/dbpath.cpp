#include "dbpath.hpp"

#include <cstdlib>

namespace ft {

std::string mithril_data_dir() {
    if (const char* db = std::getenv("MITHRIL_DB"); db && *db) return db;
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::string(xdg) + "/mithril";
    const char* home = std::getenv("HOME");
    std::string base = home && *home ? std::string(home) : ".";
    return base + "/.local/share/mithril";
}

std::string osv_index_path() { return mithril_data_dir() + "/osv-index.mdb"; }
std::string nvd_index_path() { return mithril_data_dir() + "/nvd-index.json"; }
std::string kev_index_path() { return mithril_data_dir() + "/kev.json"; }
std::string epss_index_path() { return mithril_data_dir() + "/epss.txt"; }

}  // namespace ft
