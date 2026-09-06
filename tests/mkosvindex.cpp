// mkosvindex — test/maintenance helper: read a normalized OSV index in JSON
// (the {"source","vulns":[{eco,pkg,id,sev,rel,sum,ev:[[type,ver]...]}]} shape)
// and write the compact binary index (osvindex.hpp). Used by tests/test_cve.py to
// build a fixture .mdb without reimplementing the format in Python; also converts
// a legacy osv-index.json. Ids are used as-is (fixtures are already canonical).
//
//   mkosvindex <in.json> <out.mdb>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include "io_util.hpp"
#include "jsonparse.hpp"
#include "osvindex.hpp"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <in.json> <out.mdb>\n", argv[0]);
        return 2;
    }
    auto txt = ft::read_file(argv[1]);
    if (!txt) {
        std::fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    auto doc = ft::json_parse(*txt);
    if (!doc || !doc->is_object()) {
        std::fprintf(stderr, "bad JSON: %s\n", argv[1]);
        return 1;
    }
    std::string source = doc->get_str("source");
    std::vector<ft::OsvIndexEntry> ents;
    if (const ft::JsonValue* vulns = doc->find("vulns"); vulns && vulns->is_array())
        for (const ft::JsonValue& v : vulns->arr) {
            ft::OsvIndexEntry e;
            e.eco = v.get_str("eco");
            e.pkg = v.get_str("pkg");
            if (e.eco.empty() || e.pkg.empty()) continue;
            e.id = v.get_str("id");
            e.sev = v.get_str("sev");
            e.sum = v.get_str("sum");
            e.rel = v.get_str("rel");
            if (const ft::JsonValue* ev = v.find("ev"); ev && ev->is_array())
                for (const ft::JsonValue& x : ev->arr) {
                    if (!x.is_array() || x.arr.size() < 2) continue;
                    if (!x.arr[0].is_string() || !x.arr[1].is_string()) continue;
                    const std::string& t = x.arr[0].str;
                    if (t.empty()) continue;
                    e.events.push_back({t[0], x.arr[1].str});
                }
            if (e.events.empty()) continue;
            ents.push_back(std::move(e));
        }
    std::string err;
    if (!ft::write_osv_index(argv[2], ents, static_cast<uint64_t>(std::time(nullptr)), source, err)) {
        std::fprintf(stderr, "write failed: %s\n", err.c_str());
        return 1;
    }
    return 0;
}
