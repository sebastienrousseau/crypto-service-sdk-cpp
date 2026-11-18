// SPDX-License-Identifier: Apache-2.0 OR MIT
// SPDX-FileCopyrightText: 2026 Sebastien Rousseau

#include "pattern.hpp"

#include <bitset>
#include <cstddef>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace crypto_service::kit {
namespace {

constexpr std::size_t kUnbounded = std::numeric_limits<std::size_t>::max();

// One atom: a set of characters, or a group of atoms; with its bounds.
struct Node {
  std::bitset<256> chars;
  std::vector<Node> group;
  bool is_group = false;
  std::size_t min = 1;
  std::size_t max = 1;
};

[[noreturn]] void unsupported(std::string_view pattern) {
  throw std::invalid_argument("pattern outside the supported subset: " + std::string(pattern));
}

class Parser {
 public:
  explicit Parser(std::string_view pattern) : pattern_(pattern) {}

  std::vector<Node> sequence() {
    std::vector<Node> nodes;
    while (pos_ < pattern_.size() && peek() != ')' && !at_end_anchor()) {
      Node node = atom();
      quantifier(node);
      nodes.push_back(std::move(node));
    }
    return nodes;
  }

  bool at_end_anchor() const { return peek() == '$' && pos_ + 1 == pattern_.size(); }
  bool done() const { return pos_ == pattern_.size(); }
  void skip() { ++pos_; }

 private:
  char peek() const { return pos_ < pattern_.size() ? pattern_[pos_] : '\0'; }
  char next() {
    if (pos_ >= pattern_.size()) {
      unsupported(pattern_);
    }
    return pattern_[pos_++];
  }

  Node atom() {
    Node node;
    const char c = next();
    if (c == '(') {
      node.is_group = true;
      node.group = sequence();
      if (next() != ')') {
        unsupported(pattern_);
      }
    } else if (c == '[') {
      character_class(node.chars);
    } else {
      node.chars.set(static_cast<unsigned char>(c == '\\' ? next() : c));
    }
    return node;
  }

  void character_class(std::bitset<256>& chars) {
    for (char c = next(); c != ']'; c = next()) {
      if (peek() == '-' && pos_ + 1 < pattern_.size() && pattern_[pos_ + 1] != ']') {
        skip();
        const char last = next();
        for (int x = static_cast<unsigned char>(c); x <= static_cast<unsigned char>(last); ++x) {
          chars.set(static_cast<std::size_t>(x));
        }
      } else {
        chars.set(static_cast<unsigned char>(c));
      }
    }
  }

  std::size_t number() {
    std::size_t value = 0;
    while (peek() >= '0' && peek() <= '9') {
      value = value * 10 + static_cast<std::size_t>(next() - '0');
    }
    return value;
  }

  void quantifier(Node& node) {
    const char c = peek();
    if (c == '*' || c == '+' || c == '?') {
      skip();
      node.min = c == '+' ? 1 : 0;
      node.max = c == '?' ? 1 : kUnbounded;
    } else if (c == '{') {
      skip();
      node.min = node.max = number();
      if (peek() == ',') {
        skip();
        node.max = number();
      }
      if (next() != '}') {
        unsupported(pattern_);
      }
    }
  }

  std::string_view pattern_;
  std::size_t pos_ = 0;
};

std::optional<std::size_t> match_sequence(const std::vector<Node>& nodes, std::string_view text,
                                          std::size_t pos);

// One repetition of `node` at `pos`: the position after it, or nullopt.
std::optional<std::size_t> match_once(const Node& node, std::string_view text, std::size_t pos) {
  if (node.is_group) {
    return match_sequence(node.group, text, pos);
  }
  if (pos < text.size() && node.chars.test(static_cast<unsigned char>(text[pos]))) {
    return pos + 1;
  }
  return std::nullopt;
}

std::optional<std::size_t> match_sequence(const std::vector<Node>& nodes, std::string_view text,
                                          std::size_t pos) {
  for (const Node& node : nodes) {
    std::size_t count = 0;
    while (count < node.max) {
      const std::optional<std::size_t> after = match_once(node, text, pos);
      if (!after || *after == pos) {
        break;
      }
      pos = *after;
      ++count;
    }
    if (count < node.min) {
      return std::nullopt;
    }
  }
  return pos;
}

}  // namespace

bool pattern_matches(std::string_view pattern, std::string_view text) {
  if (pattern.empty() || pattern.front() != '^') {
    unsupported(pattern);
  }
  Parser parser(pattern.substr(1));
  const std::vector<Node> nodes = parser.sequence();
  const bool anchored_end = parser.at_end_anchor();
  if (anchored_end) {
    parser.skip();
  }
  if (!parser.done()) {
    unsupported(pattern);
  }
  const std::optional<std::size_t> end = match_sequence(nodes, text, 0);
  return end && (!anchored_end || *end == text.size());
}

}  // namespace crypto_service::kit
