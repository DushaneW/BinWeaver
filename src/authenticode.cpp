// Authenticode metadata: decodes the PKCS#7 SignedData in a WIN_CERTIFICATE
// entry far enough to report the signed file digest and the signer
// certificate, and recomputes the PE image digest to compare with it.
//
// What this does NOT do: verify the signature over the signed attributes,
// build or validate a certificate chain, check revocation, timestamps or
// nested signatures. A matching digest means "the file bytes are the ones that
// were hashed when signing", not "the signature is trustworthy".
#include "internal.hpp"

#include <algorithm>

namespace bw::detail {
namespace {

// Minimal DER reader: definite lengths only, low tag numbers only.
struct Der {
    std::uint8_t tag{};
    std::span<const std::uint8_t> content;
    std::span<const std::uint8_t> whole;
};

std::optional<Der> read_der(std::span<const std::uint8_t> b, std::size_t& at) {
    if (at >= b.size() || b.size() - at < 2) return std::nullopt;
    const std::uint8_t tag = b[at];
    if ((tag & 0x1f) == 0x1f) return std::nullopt;  // high-tag-number form
    std::size_t p = at + 1;
    std::uint64_t len = b[p++];
    if (len & 0x80) {
        const std::size_t n = len & 0x7f;
        if (n == 0 || n > 4) return std::nullopt;  // indefinite length (BER) or absurd sizes
        len = 0;
        for (std::size_t k = 0; k < n; ++k) {
            if (p >= b.size()) return std::nullopt;
            len = (len << 8) | b[p++];
        }
    }
    if (len > b.size() - p) return std::nullopt;
    Der d{tag, b.subspan(p, static_cast<std::size_t>(len)), b.subspan(at, p + static_cast<std::size_t>(len) - at)};
    at = p + static_cast<std::size_t>(len);
    return d;
}

std::vector<Der> children(const Der& d, std::size_t limit = 4096) {
    std::vector<Der> out;
    std::size_t at = 0;
    while (at < d.content.size() && out.size() < limit) {
        auto c = read_der(d.content, at);
        if (!c) break;
        out.push_back(*c);
    }
    return out;
}

std::string oid(std::span<const std::uint8_t> b) {
    if (b.empty()) return {};
    std::string out = std::to_string(b[0] / 40) + "." + std::to_string(b[0] % 40);
    std::uint64_t v = 0;
    for (std::size_t i = 1; i < b.size(); ++i) {
        if (v > (std::uint64_t{1} << 56)) return out + ".?";
        v = (v << 7) | (b[i] & 0x7f);
        if (!(b[i] & 0x80)) {
            out += "." + std::to_string(v);
            v = 0;
        }
    }
    return out;
}

std::string digest_name(const std::string& o) {
    if (o == "1.3.14.3.2.26") return "SHA-1";
    if (o == "2.16.840.1.101.3.4.2.1") return "SHA-256";
    if (o == "2.16.840.1.101.3.4.2.2") return "SHA-384";
    if (o == "2.16.840.1.101.3.4.2.3") return "SHA-512";
    if (o == "1.2.840.113549.2.5") return "MD5";
    return o;
}

std::string text_value(const Der& v) {
    if (v.tag == 0x1e) {  // BMPString: UTF-16BE
        std::string out;
        for (std::size_t i = 0; i + 1 < v.content.size(); i += 2) {
            const unsigned cp = (unsigned(v.content[i]) << 8) | v.content[i + 1];
            out += cp < 0x80 ? static_cast<char>(cp) : '?';
        }
        return printable(out);
    }
    // UTF8String, PrintableString, IA5String, TeletexString: keep UTF-8 bytes,
    // escape only control characters.
    std::string out;
    for (auto c : v.content) {
        if (c < 0x20 || c == 0x7f) out += printable(std::string_view(reinterpret_cast<const char*>(&c), 1));
        else out += static_cast<char>(c);
    }
    return out;
}

// X.501 Name, rendered most-specific first like Windows ("CN=..., O=..., C=...").
std::string name_text(const Der& name) {
    std::vector<std::string> parts;
    for (const auto& rdn : children(name, 64))
        for (const auto& atv : children(rdn, 16)) {
            const auto f = children(atv, 2);
            if (f.size() != 2 || f[0].tag != 0x06) continue;
            const auto o = oid(f[0].content);
            const char* key = o == "2.5.4.3" ? "CN" : o == "2.5.4.6" ? "C" : o == "2.5.4.7" ? "L" : o == "2.5.4.8" ? "S"
                            : o == "2.5.4.10" ? "O" : o == "2.5.4.11" ? "OU" : o == "2.5.4.5" ? "SERIALNUMBER" : o == "2.5.4.9" ? "STREET"
                            : o == "1.2.840.113549.1.9.1" ? "E" : nullptr;
            parts.push_back((key ? std::string(key) : "OID." + o) + "=" + text_value(f[1]));
        }
    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) out += (out.empty() ? "" : ", ") + *it;
    return out;
}

std::string time_text(const Der& t) {
    const std::string s(t.content.begin(), t.content.end());
    std::string y, rest;
    if (t.tag == 0x17 && s.size() >= 12) {  // UTCTime YYMMDDHHMMSSZ
        const int yy = std::atoi(s.substr(0, 2).c_str());
        y = std::to_string(yy < 50 ? 2000 + yy : 1900 + yy);
        rest = s.substr(2);
    } else if (t.tag == 0x18 && s.size() >= 14) {  // GeneralizedTime YYYYMMDDHHMMSSZ
        y = s.substr(0, 4);
        rest = s.substr(4);
    } else {
        return printable(s);
    }
    return y + "-" + rest.substr(0, 2) + "-" + rest.substr(2, 2) + " " + rest.substr(4, 2) + ":" + rest.substr(6, 2) + ":" +
           rest.substr(8, 2) + " UTC";
}

struct CertFields {
    std::span<const std::uint8_t> issuer_der, serial;
    std::string subject, issuer, not_before, not_after;
};

std::optional<CertFields> parse_certificate(const Der& cert) {
    const auto top = children(cert, 3);
    if (top.empty() || top[0].tag != 0x30) return std::nullopt;
    auto tbs = children(top[0], 16);
    std::size_t i = (!tbs.empty() && tbs[0].tag == 0xa0) ? 1 : 0;  // optional [0] version
    if (tbs.size() < i + 5 || tbs[i].tag != 0x02) return std::nullopt;
    CertFields c;
    c.serial = tbs[i].content;
    c.issuer_der = tbs[i + 2].whole;
    c.issuer = name_text(tbs[i + 2]);
    const auto validity = children(tbs[i + 3], 2);
    if (validity.size() == 2) {
        c.not_before = time_text(validity[0]);
        c.not_after = time_text(validity[1]);
    }
    c.subject = name_text(tbs[i + 4]);
    return c;
}

} // namespace

void decode_authenticode(const FileImage& f, Analysis& a, std::uint64_t pkcs7_offset, std::uint64_t pkcs7_size,
                         std::uint64_t checksum_field, std::uint64_t security_entry, std::uint64_t certificate_table) {
    Signature sig;
    sig.certificate_offset = pkcs7_offset - 8;
    const auto blob = ByteView(f.bytes()).slice(pkcs7_offset, pkcs7_size);
    auto malformed = [&](const std::string& why) {
        diag(a, "pe.signature.malformed", "Certificate entry at " + hex(sig.certificate_offset) +
                                              " is not a decodable Authenticode PKCS#7 structure: " + why + ".",
             pkcs7_offset);
    };
    if (!blob) return;
    std::size_t at = 0;
    const auto content_info = read_der(*blob, at);
    if (!content_info || content_info->tag != 0x30) return malformed("no DER SEQUENCE (indefinite-length BER is not supported)");
    const auto ci = children(*content_info, 2);
    if (ci.size() != 2 || ci[0].tag != 0x06 || oid(ci[0].content) != "1.2.840.113549.1.7.2" || ci[1].tag != 0xa0)
        return malformed("not a PKCS#7 SignedData");
    const auto signed_data_list = children(ci[1], 1);
    if (signed_data_list.empty()) return malformed("empty SignedData");
    const auto sd = children(signed_data_list[0], 8);
    if (sd.size() < 4) return malformed("truncated SignedData");
    // contentInfo: SpcIndirectDataContent -> DigestInfo
    const auto inner = children(sd[2], 2);
    if (inner.size() != 2 || oid(inner[0].content) != "1.3.6.1.4.1.311.2.1.4") return malformed("missing SpcIndirectDataContent");
    const auto spc_list = children(inner[1], 1);
    const auto spc = spc_list.empty() ? std::vector<Der>{} : children(spc_list[0], 2);
    const auto digest_info = spc.size() == 2 ? children(spc[1], 2) : std::vector<Der>{};
    const auto alg = digest_info.size() == 2 ? children(digest_info[0], 2) : std::vector<Der>{};
    if (alg.empty() || digest_info[1].tag != 0x04) return malformed("missing DigestInfo");
    sig.digest_algorithm = digest_name(oid(alg[0].content));
    sig.signed_digest = hex_bytes(digest_info[1].content, 64);

    // Certificates and the signer.
    std::vector<CertFields> certs;
    const Der* signer_infos = nullptr;
    for (std::size_t i = 3; i < sd.size(); ++i) {
        if (sd[i].tag == 0xa0) {
            for (const auto& c : children(sd[i], 256))
                if (auto fields = parse_certificate(c)) certs.push_back(std::move(*fields));
        } else if (sd[i].tag == 0x31) {
            signer_infos = &sd[i];
        }
    }
    for (const auto& c : certs) sig.certificates.push_back(c.subject);
    const auto infos = signer_infos ? children(*signer_infos, 4) : std::vector<Der>{};
    const auto info = infos.empty() ? std::vector<Der>{} : children(infos[0], 3);
    const auto issuer_serial = info.size() >= 2 ? children(info[1], 2) : std::vector<Der>{};
    if (issuer_serial.size() == 2) {
        for (const auto& c : certs)
            if (std::ranges::equal(c.issuer_der, issuer_serial[0].whole) && std::ranges::equal(c.serial, issuer_serial[1].content)) {
                sig.signer_subject = c.subject;
                sig.signer_issuer = c.issuer;
                sig.signer_serial = hex_bytes(c.serial, 64);
                sig.valid_from = c.not_before;
                sig.valid_to = c.not_after;
            }
        if (sig.signer_subject.empty()) {
            sig.signer_issuer = name_text(issuer_serial[0]);
            sig.signer_serial = hex_bytes(issuer_serial[1].content, 64);
            sig.signer_subject = "<signer certificate not embedded>";
        }
    } else {
        malformed("no SignerInfo");
    }

    // Image digest: everything before the certificate table, except the
    // CheckSum field and the security directory entry.
    if (!(checksum_field + 4 <= security_entry && security_entry + 8 <= certificate_table &&
          certificate_table <= f.size())) {
        sig.digest_status = "not computed: header layout does not allow the standard digest ranges";
    } else if (sig.digest_algorithm == "SHA-256" || sig.digest_algorithm == "SHA-1") {
        const auto b = f.bytes();
        const std::pair<std::uint64_t, std::uint64_t> ranges[] = {
            {0, checksum_field}, {checksum_field + 4, security_entry}, {security_entry + 8, certificate_table}};
        if (sig.digest_algorithm == "SHA-256") {
            Sha256 h;
            for (auto [x, y] : ranges) h.update(b.subspan(static_cast<std::size_t>(x), static_cast<std::size_t>(y - x)));
            sig.computed_digest = h.hex_digest();
        } else {
            Sha1 h;
            for (auto [x, y] : ranges) h.update(b.subspan(static_cast<std::size_t>(x), static_cast<std::size_t>(y - x)));
            sig.computed_digest = h.hex_digest();
        }
        sig.digest_status = sig.computed_digest == sig.signed_digest ? "match" : "mismatch";
        if (sig.digest_status == "mismatch")
            diag(a, "pe.signature.digest_mismatch",
                 "The " + sig.digest_algorithm + " image digest does not match the signed digest: the file was modified after signing "
                 "(or uses a layout this digest computation does not model).", pkcs7_offset);
    } else {
        sig.digest_status = "not computed: " + sig.digest_algorithm + " is not implemented";
        diag(a, "pe.signature.unsupported_digest", "Authenticode digest algorithm " + sig.digest_algorithm + " is not implemented.",
             pkcs7_offset);
    }
    add_property(a, "Signer", sig.signer_subject);
    add_property(a, "Signature digest", sig.digest_algorithm + ", " + sig.digest_status);
    a.signatures.push_back(std::move(sig));
}

} // namespace bw::detail
