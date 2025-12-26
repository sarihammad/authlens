#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "third_party/json.hpp"
using json = nlohmann::json;

struct Finding {
  std::string id;
  std::string severity;
  std::string confidence;
  std::string title;
  std::string why;
  std::string fix;
  std::vector<std::string> evidence;
};

struct ParsedCookie {
  std::string name;
  std::string value;
  std::unordered_map<std::string, std::string> attrs;
};

static std::string toLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (char)std::tolower(c); });
  return s;
}

static bool containsI(const std::string &s, const std::string &sub) {
  return toLower(s).find(toLower(sub)) != std::string::npos;
}

static std::string trim(const std::string &s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  size_t end = s.find_last_not_of(" \t\r\n");
  if (start == std::string::npos || end == std::string::npos) return "";
  return s.substr(start, end - start + 1);
}

static ParsedCookie parseSetCookie(const std::string &sc) {
  ParsedCookie out;
  std::string work = sc;
  size_t start = 0;
  bool first = true;

  while (start < work.size()) {
    size_t sep = work.find(';', start);
    std::string part = trim(work.substr(start, sep == std::string::npos ? std::string::npos : sep - start));
    if (!part.empty()) {
      size_t eq = part.find('=');
      if (first) {
        first = false;
        if (eq != std::string::npos) {
          out.name = trim(part.substr(0, eq));
          out.value = trim(part.substr(eq + 1));
        } else {
          out.name = part;
        }
      } else {
        if (eq != std::string::npos) {
          out.attrs[toLower(trim(part.substr(0, eq)))] = trim(part.substr(eq + 1));
        } else {
          out.attrs[toLower(trim(part))] = "";
        }
      }
    }
    if (sep == std::string::npos) break;
    start = sep + 1;
  }

  return out;
}

static std::string urlDecode(const std::string &in) {
  std::string out;
  out.reserve(in.size());
  for (size_t i = 0; i < in.size(); i++) {
    char c = in[i];
    if (c == '+') {
      out.push_back(' ');
    } else if (c == '%' && i + 2 < in.size()) {
      auto hex = in.substr(i + 1, 2);
      char *end = nullptr;
      long val = std::strtol(hex.c_str(), &end, 16);
      if (end && *end == '\0') {
        out.push_back(static_cast<char>(val));
        i += 2;
      } else {
        out.push_back(c);
      }
    } else {
      out.push_back(c);
    }
  }
  return out;
}

static std::unordered_map<std::string, std::string> parseQueryParams(
    const std::string &url) {
  std::unordered_map<std::string, std::string> out;
  auto qpos = url.find('?');
  if (qpos == std::string::npos) return out;
  auto end = url.find('#', qpos);
  std::string q =
      url.substr(qpos + 1,
                 end == std::string::npos ? std::string::npos : end - (qpos + 1));

  size_t i = 0;
  while (i < q.size()) {
    size_t amp = q.find('&', i);
    std::string kv = q.substr(i, amp == std::string::npos ? std::string::npos : amp - i);
    size_t eq = kv.find('=');
    if (eq != std::string::npos) {
      out[urlDecode(kv.substr(0, eq))] = urlDecode(kv.substr(eq + 1));
    } else if (!kv.empty()) {
      out[urlDecode(kv)] = "";
    }
    if (amp == std::string::npos) break;
    i = amp + 1;
  }
  return out;
}

static std::unordered_map<std::string, std::string> parseFragmentParams(
    const std::string &url) {
  std::unordered_map<std::string, std::string> out;
  auto hpos = url.find('#');
  if (hpos == std::string::npos || hpos + 1 >= url.size()) return out;
  std::string f = url.substr(hpos + 1);

  size_t i = 0;
  while (i < f.size()) {
    size_t amp = f.find('&', i);
    std::string kv = f.substr(i, amp == std::string::npos ? std::string::npos : amp - i);
    size_t eq = kv.find('=');
    if (eq != std::string::npos) {
      out[urlDecode(kv.substr(0, eq))] = urlDecode(kv.substr(eq + 1));
    } else if (!kv.empty()) {
      out[urlDecode(kv)] = "";
    }
    if (amp == std::string::npos) break;
    i = amp + 1;
  }
  return out;
}

static void add(std::vector<Finding> &out, Finding f) {
  out.push_back(std::move(f));
}

static std::string getUrl(const json &ev) {
  if (ev.contains("url") && ev["url"].is_string()) return ev["url"].get<std::string>();
  return "";
}

static std::vector<std::string> getHeaderValues(const json &responseHeaders,
                                                const std::string &headerName) {
  std::vector<std::string> out;
  std::string target = toLower(headerName);

  if (responseHeaders.is_array()) {
    for (const auto &h : responseHeaders) {
      if (!h.is_object()) continue;
      if (!h.contains("name") || !h.contains("value")) continue;
      if (!h["name"].is_string() || !h["value"].is_string()) continue;
      if (toLower(h["name"].get<std::string>()) == target) {
        out.push_back(h["value"].get<std::string>());
      }
    }
  } else if (responseHeaders.is_object()) {
    for (auto it = responseHeaders.begin(); it != responseHeaders.end(); ++it) {
      if (toLower(it.key()) == target && it.value().is_string()) {
        out.push_back(it.value().get<std::string>());
      }
    }
  }
  return out;
}

static json makeReport(const json &trace, const std::vector<Finding> &findings) {
  int hi = 0, med = 0, low = 0;
  for (const auto &f : findings) {
    if (f.severity == "HIGH") hi++;
    else if (f.severity == "MED") med++;
    else low++;
  }

  json j;
  j["version"] = 1;
  j["tabId"] = trace.value("tabId", -1);
  j["startedAtMs"] = trace.value("startedAtMs", 0);
  j["summary"] = {{"HIGH", hi}, {"MED", med}, {"LOW", low}};
  j["findings"] = json::array();
  for (const auto &f : findings) {
    j["findings"].push_back({
        {"id", f.id},
        {"severity", f.severity},
        {"confidence", f.confidence},
        {"title", f.title},
        {"why", f.why},
        {"fix", f.fix},
        {"evidence", f.evidence},
    });
  }
  return j;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cerr << "Usage: authlens analyze <trace.json> [--out report.json]\n";
    return 1;
  }
  std::string cmd = argv[1];
  if (cmd != "analyze") {
    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
  }

  std::string tracePath = argv[2];
  std::string outPath = "report.json";
  for (int i = 3; i < argc; i++) {
    if (std::string(argv[i]) == "--out" && i + 1 < argc) outPath = argv[++i];
  }

  std::ifstream in(tracePath);
  if (!in) {
    std::cerr << "Failed to open trace: " << tracePath << "\n";
    return 1;
  }

  json trace;
  try {
    in >> trace;
  } catch (const std::exception &e) {
    std::cerr << "Failed to parse JSON: " << e.what() << "\n";
    return 1;
  }

  if (!trace.contains("events") || !trace["events"].is_array()) {
    std::cerr << "Trace missing events array.\n";
    return 1;
  }

  std::vector<Finding> findings;

  bool sawAuthorize = false;
  bool sawTokenEndpoint = false;

  bool pkceSeen = false;
  bool pkceS256 = true;

  bool callbackHasCode = false;
  bool callbackHasState = false;
  bool callbackStateMismatch = false;
  std::optional<std::string> authorizeState;
  std::optional<std::string> callbackState;

  bool oidcAuthorize = false;
  bool authorizeHasNonce = false;

  bool tokenBodyObserved = false;
  bool tokenHasCodeVerifier = false;

  for (const auto &ev : trace["events"]) {
    std::string url = getUrl(ev);
    if (url.empty()) continue;

    if (containsI(url, "/oauth/authorize") || containsI(url, "/authorize")) {
      sawAuthorize = true;

      auto q = parseQueryParams(url);
      if (q.find("state") != q.end()) authorizeState = q["state"];
      if (q.find("code_challenge") != q.end()) pkceSeen = true;
      if (q.find("code_challenge_method") != q.end()) {
        std::string m = q["code_challenge_method"];
        if (toLower(m) != "s256") pkceS256 = false;
      }

      if (q.find("nonce") != q.end()) authorizeHasNonce = true;
      const bool responseTypeOidc =
          q.find("response_type") != q.end() && containsI(q["response_type"], "id_token");
      const bool scopeOidc =
          q.find("scope") != q.end() && containsI(q["scope"], "openid");
      if (responseTypeOidc || scopeOidc) oidcAuthorize = true;
    }

    if (containsI(url, "/oauth/token") ||
        (containsI(url, "/token") && !containsI(url, "/authorize"))) {
      sawTokenEndpoint = true;
    }

    auto q = parseQueryParams(url);
    auto f = parseFragmentParams(url);

    auto hasKey = [&](const std::unordered_map<std::string, std::string> &m,
                      const std::string &k) { return m.find(k) != m.end(); };

    if (hasKey(q, "access_token") || hasKey(q, "id_token") || hasKey(q, "refresh_token")) {
      add(findings, {"TOKEN_IN_QUERY", "HIGH", "HIGH",
                     "Token appears in URL query string",
                     "URLs are logged and can leak via referrer headers.",
                     "Do not put tokens in URLs. Use Authorization header or secure cookies.",
                     {url}});
    }

    if (hasKey(f, "access_token") || hasKey(f, "id_token")) {
      add(findings, {"TOKEN_IN_FRAGMENT", "MED", "MED",
                     "Token appears in URL fragment",
                     "Fragments can be exposed to browser history or extensions.",
                     "Avoid implicit/hybrid flows; use Authorization Code + PKCE.",
                     {url}});
    }

    if (hasKey(q, "code") || hasKey(f, "code")) callbackHasCode = true;
    if (hasKey(q, "state") || hasKey(f, "state")) {
      callbackHasState = true;
      if (hasKey(q, "state")) callbackState = q["state"];
      else if (hasKey(f, "state")) callbackState = f["state"];
      if (authorizeState && callbackState && *authorizeState != *callbackState) {
        callbackStateMismatch = true;
      }
    }

    if (containsI(url, "/oauth/token") ||
        (containsI(url, "/token") && !containsI(url, "/authorize"))) {
      if (ev.contains("requestBodyKeys") && ev["requestBodyKeys"].is_array()) {
        tokenBodyObserved = true;
        for (const auto &k : ev["requestBodyKeys"]) {
          if (!k.is_string()) continue;
          std::string key = toLower(k.get<std::string>());
          if (key == "code_verifier") tokenHasCodeVerifier = true;
        }
      }
    }

    if (ev.contains("responseHeaders")) {
      const auto &rh = ev["responseHeaders"];

      const auto setCookies = getHeaderValues(rh, "set-cookie");
      for (const auto &sc : setCookies) {
        ParsedCookie cookie = parseSetCookie(sc);
        const auto &attrs = cookie.attrs;

        bool secure = attrs.find("secure") != attrs.end();
        bool httponly = attrs.find("httponly") != attrs.end();
        std::string samesite = "";
        if (attrs.find("samesite") != attrs.end()) samesite = toLower(attrs.at("samesite"));
        bool samesiteNone = samesite == "none";
        bool hasExpires = attrs.find("expires") != attrs.end();
        bool hasMaxAge = attrs.find("max-age") != attrs.end();
        bool sessionish = (!hasExpires && !hasMaxAge) ||
                          containsI(cookie.name, "sid") ||
                          containsI(cookie.name, "sess") ||
                          containsI(cookie.name, "session");

        if (sessionish) {
          if (!secure) {
            add(findings, {"COOKIE_MISSING_SECURE", "MED", "MED",
                           "Session cookie missing Secure",
                           "Session cookies without Secure can be sent over HTTP.",
                           "Mark session cookies Secure (and serve over HTTPS).",
                           {sc}});
          }
          if (!httponly) {
            add(findings, {"COOKIE_MISSING_HTTPONLY", "MED", "MED",
                           "Session cookie missing HttpOnly",
                           "Missing HttpOnly increases risk of XSS token theft.",
                           "Mark session cookies HttpOnly to reduce XSS token theft risk.",
                           {sc}});
          }
        }

        if (samesiteNone && !secure) {
          add(findings, {"SAMESITE_NONE_WITHOUT_SECURE", "HIGH", "HIGH",
                         "SameSite=None cookie without Secure",
                         "Browsers reject SameSite=None cookies without Secure.",
                         "Chrome requires Secure when SameSite=None. Add Secure or change SameSite.",
                         {sc}});
        }
      }
    }
  }

  if (callbackHasCode && !callbackHasState) {
    add(findings, {"STATE_MISSING", "HIGH", "HIGH",
                   "Callback has code but no state",
                   "State is required to prevent CSRF and code injection.",
                   "Always include and validate state to prevent CSRF/code injection.",
                   {}});
  }

  if (callbackStateMismatch) {
    add(findings, {"STATE_MISMATCH", "HIGH", "HIGH",
                   "Callback state does not match authorize state",
                   "Mismatched state indicates possible request forgery.",
                   "Reject callbacks with unexpected state values.",
                   {}});
  }

  if (oidcAuthorize && !authorizeHasNonce) {
    add(findings, {"NONCE_MISSING", "HIGH", "HIGH",
                   "Authorize request missing nonce",
                   "OIDC requires nonce to prevent token replay.",
                   "Include a nonce for OIDC flows and validate it in the ID token.",
                   {}});
  }

  if (sawAuthorize && !pkceSeen) {
    add(findings, {"PKCE_MISSING", "HIGH", "HIGH",
                   "Authorize request missing PKCE code_challenge",
                   "PKCE mitigates code interception attacks for public clients.",
                   "For public clients, require Authorization Code + PKCE and validate code_verifier at token exchange.",
                   {}});
  } else if (sawAuthorize && pkceSeen && !pkceS256) {
    add(findings, {"PKCE_NOT_S256", "MED", "MED",
                   "PKCE code_challenge_method is not S256",
                   "S256 is the recommended PKCE method.",
                   "Prefer S256 for PKCE. Avoid 'plain' except in constrained environments.",
                   {}});
  }

  if (sawAuthorize && !sawTokenEndpoint) {
    add(findings, {"AUTHORIZE_BUT_NO_TOKEN", "LOW", "LOW",
                   "Authorize flow detected but token exchange not observed",
                   "Missing token exchange may indicate failed flow or sampling gaps.",
                   "If using Authorization Code flow, ensure the client exchanges the code at the token endpoint.",
                   {}});
  }

  if (sawTokenEndpoint && tokenBodyObserved && !tokenHasCodeVerifier) {
    add(findings, {"PKCE_VERIFIER_MISSING", "MED", "MED",
                   "Token request missing code_verifier",
                   "Missing code_verifier prevents PKCE validation.",
                   "Include code_verifier in token requests for Authorization Code + PKCE.",
                   {}});
  }

  json report = makeReport(trace, findings);

  std::ofstream out(outPath);
  if (!out) {
    std::cerr << "Failed to open output file: " << outPath << "\n";
    return 1;
  }
  out << report.dump(2) << "\n";

  std::cout << "Findings: HIGH=" << report["summary"]["HIGH"]
            << " MED=" << report["summary"]["MED"]
            << " LOW=" << report["summary"]["LOW"] << "\n";
  std::cout << "Wrote: " << outPath << "\n";
  return 0;
}
