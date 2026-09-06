#include "sbom_emit.hpp"

#include <ctime>
#include <string>

#include "strutil.hpp"

namespace ft {

namespace {

void quoted(std::string& o, const std::string& s) {
    o += '"';
    json_escape(o, s);
    o += '"';
}

// SPDXID allows only letters, digits, '.' and '-'. Index-based ids are safest.
std::string utc_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

}  // namespace

std::string emit_cyclonedx(const std::vector<Component>& components,
                           const std::string& tool_version) {
    std::string o;
    o += "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,";
    o += "\"metadata\":{\"tools\":[{\"vendor\":\"mithril\",\"name\":\"mithril\",\"version\":";
    quoted(o, tool_version);
    o += "}]},\"components\":[";
    for (size_t i = 0; i < components.size(); ++i) {
        const Component& c = components[i];
        if (i) o += ",";
        o += "{\"type\":";
        quoted(o, c.type);
        o += ",\"name\":";
        quoted(o, c.name);
        if (!c.version.empty()) {
            o += ",\"version\":";
            quoted(o, c.version);
        }
        if (!c.purl.empty()) {
            o += ",\"purl\":";
            quoted(o, c.purl);
        }
        if (!c.cpe.empty()) {
            o += ",\"cpe\":";
            quoted(o, c.cpe);
        }
        if (!c.license.empty()) {
            o += ",\"licenses\":[{\"license\":{\"name\":";
            quoted(o, c.license);
            o += "}}]";
        }
        // mithril provenance as properties (source, origin file, confidence).
        o += ",\"properties\":[{\"name\":\"mithril:source\",\"value\":";
        quoted(o, c.source);
        o += "},{\"name\":\"mithril:origin\",\"value\":";
        quoted(o, c.origin_path);
        o += "},{\"name\":\"mithril:confidence\",\"value\":";
        quoted(o, std::to_string(c.confidence));
        o += "}]}";
    }
    o += "]}";
    return o;
}

std::string emit_spdx(const std::vector<Component>& components, const std::string& tool_version) {
    std::string o;
    const std::string ts = utc_now();
    o += "{\"spdxVersion\":\"SPDX-2.3\",\"dataLicense\":\"CC0-1.0\",";
    o += "\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"mithril-sbom\",";
    o += "\"documentNamespace\":\"https://mithril.invalid/sbom/";
    json_escape(o, ts);
    o += "\",\"creationInfo\":{\"created\":\"";
    json_escape(o, ts);
    o += "\",\"creators\":[\"Tool: mithril-";
    json_escape(o, tool_version);
    o += "\"]},\"packages\":[";
    for (size_t i = 0; i < components.size(); ++i) {
        const Component& c = components[i];
        if (i) o += ",";
        std::string id = "SPDXRef-Package-" + std::to_string(i);
        o += "{\"SPDXID\":";
        quoted(o, id);
        o += ",\"name\":";
        quoted(o, c.name);
        if (!c.version.empty()) {
            o += ",\"versionInfo\":";
            quoted(o, c.version);
        }
        o += ",\"downloadLocation\":\"NOASSERTION\",\"filesAnalyzed\":false";
        o += ",\"licenseConcluded\":\"NOASSERTION\"";
        o += ",\"licenseDeclared\":";
        quoted(o, c.license.empty() ? "NOASSERTION" : c.license);
        if (!c.purl.empty()) {
            o += ",\"externalRefs\":[{\"referenceCategory\":\"PACKAGE-MANAGER\","
                 "\"referenceType\":\"purl\",\"referenceLocator\":";
            quoted(o, c.purl);
            o += "}]";
        }
        o += "}";
    }
    o += "],\"documentDescribes\":[";
    for (size_t i = 0; i < components.size(); ++i) {
        if (i) o += ",";
        quoted(o, "SPDXRef-Package-" + std::to_string(i));
    }
    o += "]}";
    return o;
}

}  // namespace ft
