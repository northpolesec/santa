/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

/*

Benchmark different SQL query strategies for execution rule lookups.

Generate a test database:
  bazel-bin/Testing/OneOffs/rule_query_bench -g 100000 -d /tmp/rule_bench.db

Run benchmarks with hyperfine:
  BENCH=bazel-bin/Testing/OneOffs/rule_query_bench
  STRATEGIES=none,implicit,orderby,separate,unionall,unionallorderby,unionallprio,unionallcase
  LOOKUPS=cdhash,teamid,miss,multimatch,transitive,shadowed,mixed
  /opt/homebrew/bin/hyperfine --warmup 10 \
      --parameter-list strategy $STRATEGIES \
      --parameter-list lookup $LOOKUPS \
      "$BENCH -i 10000 -t {strategy} -l {lookup} -d /tmp/rule_bench.db"

IMPORTANT -- how to turn a run into a per-query number:

Each run measures whole-process time, which includes both a fixed cost (process launch, opening
the DB) and a PER-ITERATION cost that is not the query (generating one random identifier set per
iteration). Subtract the `none` strategy at the SAME `-i`, which pays both of those and runs no
query:

    per_query = (T(strategy, N) - T(none, N)) / N

Do NOT use an `-i 1` run as the baseline. Identifier generation scales with `-i`, so an `-i 1`
baseline removes almost none of it and what is left lands in the "per-query" figure instead.
That mistake inflated the numbers recorded on SNT-391 by roughly 4x.

Comparing two strategies at the same `-i` is also safe without any baseline, since the non-query
cost is identical and cancels in the difference.

Between-invocation drift on a loaded machine is ~0.3us/query, larger than the within-invocation
standard error hyperfine reports. Deltas below ~0.5us/query need several independent hyperfine
invocations pooled before they mean anything, and nothing else should be running.

Strategies:
  none            - Runs no query. Establishes the non-query cost (process launch, opening the
                    DB, and the per-iteration identifier generation) for a given -i. Subtract it
                    from another strategy at the same -i to recover the true per-query cost.
  implicit        - OR clauses + LIMIT 1, no ORDER BY. Relies on SQLite's query planner
                    evaluating OR clauses left-to-right -- empirically correct but not
                    guaranteed. A query planner change could silently break precedence.
  orderby         - Same OR clauses with ORDER BY type ASC. Guaranteed correct, but forces
                    SQLite to evaluate all 5 branches and sort before returning.
  separate        - Five individual queries executed in priority order with early return.
                    Guaranteed correct (precedence is in ObjC code, not SQL), but pays FMDB
                    per-query overhead for each round-trip.
  unionall        - UNION ALL of five selects in priority order + LIMIT 1. Practically
                    correct -- UNION ALL concatenation order is preserved in all known SQLite
                    versions, but the SQL spec does not formally guarantee row order without
                    ORDER BY.
  unionallorderby - UNION ALL of five selects wrapped in a subquery with ORDER BY type ASC
                    + LIMIT 1. Guaranteed correct by ORDER BY, and the UNION ALL structure
                    gives SQLite more optimization freedom than the flat OR approach.
                    This was the production strategy before transitive rules were demoted.
  unionallprio    - unionallorderby, but the Binary sub-select is split on `state` and the sort
                    key is a constant `prio` per sub-select, so transitive Binary rules rank
                    below every other type instead of ranking as Binary. Keeps the naturally
                    ordered compound query (streaming MERGE, no temp B-tree) at the cost of one
                    extra index seek on (binarySHA256, 1000), paid on EVERY lookup -- see the
                    note below on LIMIT 1.
                    This is the strategy used in production (see SNTRuleTable.mm).
  unionallcase    - Same demotion via ORDER BY CASE WHEN state=... over the original five
                    sub-selects. Avoids the extra seek, but the sort key is opaque to the
                    planner, so SQLite materializes the union and adds a temp B-tree sort.

The last two exist because a transitive Binary rule must not outrank a configured Signing ID /
Certificate / Team ID rule for the same executable -- see issue #1123, where a Go toolchain
unpacked by another compiler stopped being treated as a compiler.

LIMIT 1 is not an early-out. Under the MERGE (UNION ALL) plan SQLite steps every branch to
determine which sorts first, so all of them do their index seek regardless of whether a
higher-priority branch matched. Verified with a counting SQL function in the last branch: it is
invoked even when the prio-1 CDHash branch matches. Consequently the strategies differ by a
roughly CONSTANT amount across lookup types -- there is no "cheap" lookup that skips the extra
work, and measured deltas being flat across lookup types is the expected result, not a bug in the
measurement.

Lookup types:
  cdhash      - Hit on CDHash rule (highest priority)
  binary      - Hit on Binary rule
  signingid   - Hit on SigningID rule
  certificate - Hit on Certificate rule
  teamid      - Hit on TeamID rule (lowest priority)
  multimatch  - Hits on SigningID + Certificate + TeamID simultaneously (tests ordering correctness)
  transitive  - Hit on a transitive Binary rule and nothing else. Exercises the extra sub-select
                actually producing the winning row.
  shadowed    - Hit on both a transitive Binary rule and a SigningID rule (the issue #1123 case).
                unionall/unionallorderby return the transitive rule here; unionallprio and
                unionallcase return the SigningID rule.
  miss        - No matching rule exists.
  mixed       - Uniform random mix of all the above

Note: Miss identifiers are randomly generated per-iteration to avoid B-tree page cache
effects from repeatedly querying the same absent keys. Hit identifiers for non-hit slots
are also randomized per-iteration for the same reason.

*/

#import <Foundation/Foundation.h>
#import <fmdb/FMDB.h>

#include <getopt.h>
#include <stdlib.h>

#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <vector>

// Rule types matching SNTRuleType enum values
static const int kRuleTypeCDHash = 500;
static const int kRuleTypeBinary = 1000;
static const int kRuleTypeSigningID = 2000;
static const int kRuleTypeCertificate = 3000;
static const int kRuleTypeTeamID = 4000;

static const int kRuleStateAllow = 1;
static const int kRuleStateAllowTransitive = 6;

// Fraction of generated Binary rules given state=AllowTransitive. Transitive rules are written
// locally by the compiler controller, so on a developer machine they make up a large share of the
// Binary rules. `state` is not part of execution_rules_unique, so varying this changes only row
// composition, never row count or index shape -- results stay comparable to runs that predate the
// transitive strategies.
static const double kTransitiveBinaryFraction = 0.5;

static const uint32_t kSeed = 0xBEEFCAFE;

#pragma mark - Known identifiers for single-type hit testing

static NSString* const kKnownCDHash = @"aabbccdd00112233445566778899aabbccddeeff";
static NSString* const kKnownBinary =
    @"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
static NSString* const kKnownSigningID = @"BENCHTEST1:com.example.benchmark.known";
static NSString* const kKnownCertificate =
    @"feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
static NSString* const kKnownTeamID = @"BENCHTEST1";

#pragma mark - Known identifiers for multi-match testing

// Simulates a binary that has rules at SigningID, Certificate, and TeamID levels
// simultaneously. The correct result is the SigningID rule (highest priority among
// the three). CDHash and Binary slots will use random misses.
static NSString* const kMultiSigningID = @"MULTITEST1:com.example.benchmark.multi";
static NSString* const kMultiCertificate =
    @"1111111111111111111111111111111111111111111111111111111111111111";
static NSString* const kMultiTeamID = @"MULTITEST1";

#pragma mark - Known identifiers for transitive rule testing

// A Binary rule with state=AllowTransitive and nothing else matching. Every sub-select must be
// evaluated before this is found, so this is the worst case for the prio strategy's extra
// Binary sub-select.
static NSString* const kTransitiveBinary =
    @"2222222222222222222222222222222222222222222222222222222222222222";

// The GOTOOLCHAIN=auto case from issue #1123: a binary carrying both a locally-written transitive
// Binary rule and a configured SigningID rule. `unionall`/`unionallorderby` rank the transitive
// rule by its Binary type and return it; `unionallprio`/`unionallcase` return the SigningID rule.
static NSString* const kShadowedBinary =
    @"3333333333333333333333333333333333333333333333333333333333333333";
static NSString* const kShadowedSigningID = @"SHADOWTEST:com.example.benchmark.shadowed";

#pragma mark - Enums and config

enum class Strategy {
  kNone,
  kImplicit,
  kOrderBy,
  kSeparate,
  kUnionAll,
  kUnionAllOrderBy,
  kUnionAllPrio,
  kUnionAllCase,
};

enum class LookupType {
  kCDHash,
  kBinary,
  kSigningID,
  kCertificate,
  kTeamID,
  kMultiMatch,
  kTransitive,
  kShadowed,
  kMiss,
  kMixed,
};

struct Config {
  int generateCount = 0;
  int iterations = 1000;
  Strategy strategy = Strategy::kImplicit;
  LookupType lookup = LookupType::kMixed;
  NSString* dbPath = @"/tmp/rule_bench.db";
  bool verbose = false;
};

struct LookupIdentifiers {
  NSString* cdhash;
  NSString* binarySHA256;
  NSString* signingID;
  NSString* certificateSHA256;
  NSString* teamID;
};

#pragma mark - Random data generation

// Fills a stack buffer and creates the NSString once. An earlier version appended one
// -appendFormat: per character, which cost ~36us per lookup set -- an order of magnitude more
// than the queries under test, diluting every strategy comparison into the noise.
static NSString* RandomHex(int length, std::mt19937& gen) {
  static const char hex[] = "0123456789abcdef";
  std::uniform_int_distribution<> dist(0, 15);
  char buf[128];
  // Abort rather than clamp. Silently returning a shorter identifier would populate the
  // database with wrong-length identifiers and raise the collision rate under INSERT OR
  // IGNORE, quietly changing the row counts the benchmark is characterizing.
  if (length < 0 || length > (int)sizeof(buf)) {
    std::cerr << "Error: RandomHex length " << length << " out of range (max " << sizeof(buf) << ")"
              << std::endl;
    abort();
  }
  for (int i = 0; i < length; i++) {
    buf[i] = hex[dist(gen)];
  }
  return [[NSString alloc] initWithBytes:buf length:length encoding:NSASCIIStringEncoding];
}

static NSString* RandomTeamID(std::mt19937& gen) {
  static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  std::uniform_int_distribution<> dist(0, (int)strlen(chars) - 1);
  char buf[11];
  for (int i = 0; i < 10; i++) {
    buf[i] = chars[dist(gen)];
  }
  buf[10] = '\0';
  return [NSString stringWithUTF8String:buf];
}

static NSString* RandomSigningID(std::mt19937& gen) {
  static const char teamChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  static const char hex[] = "0123456789abcdef";
  static const char kInfix[] = ":com.example.bench.";
  std::uniform_int_distribution<> teamDist(0, (int)strlen(teamChars) - 1);
  std::uniform_int_distribution<> hexDist(0, 15);

  // "<10 team chars>:com.example.bench.<8 hex>", assembled in one pass.
  char buf[10 + sizeof(kInfix) - 1 + 8];
  char* p = buf;
  for (int i = 0; i < 10; i++) {
    *p++ = teamChars[teamDist(gen)];
  }
  memcpy(p, kInfix, sizeof(kInfix) - 1);
  p += sizeof(kInfix) - 1;
  for (int i = 0; i < 8; i++) {
    *p++ = hex[hexDist(gen)];
  }
  return [[NSString alloc] initWithBytes:buf length:sizeof(buf) encoding:NSASCIIStringEncoding];
}

// Generate a full set of random identifiers that will not match any known rules.
// Used as the base for every lookup iteration -- hit tests overlay known identifiers
// on top of this random base.
static LookupIdentifiers RandomMissIdentifiers(std::mt19937& gen) {
  return {
      .cdhash = RandomHex(40, gen),
      .binarySHA256 = RandomHex(64, gen),
      .signingID = RandomSigningID(gen),
      .certificateSHA256 = RandomHex(64, gen),
      .teamID = RandomTeamID(gen),
  };
}

#pragma mark - Database generation

static void GenerateDatabase(const Config& config) {
  [[NSFileManager defaultManager] removeItemAtPath:config.dbPath error:nil];

  FMDatabase* db = [FMDatabase databaseWithPath:config.dbPath];
  if (![db open]) {
    std::cerr << "Error: Failed to create database at " << config.dbPath.UTF8String << std::endl;
    exit(1);
  }

  [db executeUpdate:@"CREATE TABLE 'execution_rules' ("
                    @"'identifier' TEXT NOT NULL, "
                    @"'state' INTEGER NOT NULL, "
                    @"'type' INTEGER NOT NULL, "
                    @"'timestamp' INTEGER, "
                    @"'customurl' TEXT, "
                    @"'custommsg' TEXT, "
                    @"'comment' TEXT, "
                    @"'cel_expr' TEXT, "
                    @"'rule_id' INTEGER DEFAULT 0"
                    @")"];
  [db executeUpdate:
          @"CREATE UNIQUE INDEX execution_rules_unique ON execution_rules ('identifier', type)"];

  std::mt19937 gen(kSeed);

  // Distribution weighted to match typical real-world rule databases:
  // Binary-heavy with a decent number of certificate rules.
  //   CDHash: 5%, Binary: 40%, SigningID: 15%, Certificate: 30%, TeamID: 10%
  std::discrete_distribution<> typeDist({5, 40, 15, 30, 10});
  int types[] = {kRuleTypeCDHash, kRuleTypeBinary, kRuleTypeSigningID, kRuleTypeCertificate,
                 kRuleTypeTeamID};

  [db beginTransaction];

  // Insert single-hit known rules (one per type)
  NSArray* knownIds =
      @[ kKnownCDHash, kKnownBinary, kKnownSigningID, kKnownCertificate, kKnownTeamID ];
  for (int i = 0; i < 5; i++) {
    [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                      knownIds[i], @(kRuleStateAllow), @(types[i])];
  }

  // Insert multi-match known rules (3 rules that all match the same conceptual binary)
  [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                    kMultiSigningID, @(kRuleStateAllow), @(kRuleTypeSigningID)];
  [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                    kMultiCertificate, @(kRuleStateAllow), @(kRuleTypeCertificate)];
  [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                    kMultiTeamID, @(kRuleStateAllow), @(kRuleTypeTeamID)];

  // Insert transitive known rules: one standalone, and one shadowing a SigningID rule.
  [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                    kTransitiveBinary, @(kRuleStateAllowTransitive), @(kRuleTypeBinary)];
  [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                    kShadowedBinary, @(kRuleStateAllowTransitive), @(kRuleTypeBinary)];
  [db executeUpdate:@"INSERT INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
                    kShadowedSigningID, @(kRuleStateAllow), @(kRuleTypeSigningID)];

  std::bernoulli_distribution transitiveDist(kTransitiveBinaryFraction);

  // Insert random rules
  for (int i = 0; i < config.generateCount; i++) {
    int typeIdx = typeDist(gen);
    int type = types[typeIdx];
    NSString* identifier;

    switch (type) {
      case kRuleTypeCDHash: identifier = RandomHex(40, gen); break;
      case kRuleTypeBinary: identifier = RandomHex(64, gen); break;
      case kRuleTypeSigningID: identifier = RandomSigningID(gen); break;
      case kRuleTypeCertificate: identifier = RandomHex(64, gen); break;
      case kRuleTypeTeamID: identifier = RandomTeamID(gen); break;
      default: __builtin_unreachable();
    }

    // Only Binary rules can be transitive.
    int state = (type == kRuleTypeBinary && transitiveDist(gen)) ? kRuleStateAllowTransitive
                                                                 : kRuleStateAllow;

    [db executeUpdate:
            @"INSERT OR IGNORE INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
            identifier, @(state), @(type)];

    if (i > 0 && i % 50000 == 0) {
      [db commit];
      [db beginTransaction];
      if (config.verbose) {
        std::cout << "  Inserted " << i << " / " << config.generateCount << "..." << std::endl;
      }
    }
  }

  [db commit];

  // Print summary
  FMResultSet* rs = [db executeQuery:@"SELECT type, COUNT(*) as cnt FROM execution_rules "
                                     @"GROUP BY type ORDER BY type"];
  int total = 0;
  std::cout << "Database: " << config.dbPath.UTF8String << std::endl;
  std::cout << "Rule counts by type:" << std::endl;
  while ([rs next]) {
    int type = [rs intForColumn:@"type"];
    int count = [rs intForColumn:@"cnt"];
    total += count;
    const char* name = "Unknown";
    switch (type) {
      case kRuleTypeCDHash: name = "CDHash     "; break;
      case kRuleTypeBinary: name = "Binary     "; break;
      case kRuleTypeSigningID: name = "SigningID  "; break;
      case kRuleTypeCertificate: name = "Certificate"; break;
      case kRuleTypeTeamID: name = "TeamID     "; break;
    }
    std::cout << "  " << name << " (" << type << "): " << count << std::endl;
  }
  [rs close];
  std::cout << "  Total: " << total << std::endl;

  std::cout << "  (of which transitive: " <<
      [db longForQuery:@"SELECT COUNT(*) FROM execution_rules WHERE state=?",
                       @(kRuleStateAllowTransitive)]
            << ")" << std::endl;

  [db close];
}

#pragma mark - Lookup identifier construction

// Build a LookupIdentifiers for one iteration. Starts with random miss identifiers
// for all 5 slots, then overlays the known hit identifier(s) for the requested type.
static LookupIdentifiers BuildLookup(LookupType type, std::mt19937& gen) {
  LookupIdentifiers ids = RandomMissIdentifiers(gen);

  switch (type) {
    case LookupType::kCDHash: ids.cdhash = kKnownCDHash; break;
    case LookupType::kBinary: ids.binarySHA256 = kKnownBinary; break;
    case LookupType::kSigningID: ids.signingID = kKnownSigningID; break;
    case LookupType::kCertificate: ids.certificateSHA256 = kKnownCertificate; break;
    case LookupType::kTeamID: ids.teamID = kKnownTeamID; break;
    case LookupType::kMultiMatch:
      ids.signingID = kMultiSigningID;
      ids.certificateSHA256 = kMultiCertificate;
      ids.teamID = kMultiTeamID;
      break;
    case LookupType::kTransitive: ids.binarySHA256 = kTransitiveBinary; break;
    case LookupType::kShadowed:
      ids.binarySHA256 = kShadowedBinary;
      ids.signingID = kShadowedSigningID;
      break;
    case LookupType::kMiss: break;
    case LookupType::kMixed: break;  // handled by caller
  }
  return ids;
}

#pragma mark - Query strategies

// Runs no query at all. Establishes the harness floor for a given -i: process launch, building
// the lookup vector, and opening the DB. Subtract it from another strategy at the same -i to get
// that strategy's true per-query cost, instead of a number diluted by harness overhead.
static BOOL QueryNone(FMDatabase* db, const LookupIdentifiers& ids) {
  return NO;
}

static BOOL QueryImplicit(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs = [db executeQuery:@"SELECT * FROM execution_rules WHERE "
                                     @"   (identifier=? AND type=500) "
                                     @"OR (identifier=? AND type=1000) "
                                     @"OR (identifier=? AND type=2000) "
                                     @"OR (identifier=? AND type=3000) "
                                     @"OR (identifier=? AND type=4000) LIMIT 1",
                                     ids.cdhash, ids.binarySHA256, ids.signingID,
                                     ids.certificateSHA256, ids.teamID];
  BOOL found = [rs next];
  [rs close];
  return found;
}

static BOOL QueryOrderBy(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs = [db executeQuery:@"SELECT * FROM execution_rules WHERE "
                                     @"   (identifier=? AND type=500) "
                                     @"OR (identifier=? AND type=1000) "
                                     @"OR (identifier=? AND type=2000) "
                                     @"OR (identifier=? AND type=3000) "
                                     @"OR (identifier=? AND type=4000) ORDER BY type ASC LIMIT 1",
                                     ids.cdhash, ids.binarySHA256, ids.signingID,
                                     ids.certificateSHA256, ids.teamID];
  BOOL found = [rs next];
  [rs close];
  return found;
}

static BOOL QuerySeparate(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs;

  rs = [db
      executeQuery:@"SELECT * FROM execution_rules WHERE identifier=? AND type=500", ids.cdhash];
  if ([rs next]) {
    [rs close];
    return YES;
  }
  [rs close];

  rs = [db executeQuery:@"SELECT * FROM execution_rules WHERE identifier=? AND type=1000",
                        ids.binarySHA256];
  if ([rs next]) {
    [rs close];
    return YES;
  }
  [rs close];

  rs = [db executeQuery:@"SELECT * FROM execution_rules WHERE identifier=? AND type=2000",
                        ids.signingID];
  if ([rs next]) {
    [rs close];
    return YES;
  }
  [rs close];

  rs = [db executeQuery:@"SELECT * FROM execution_rules WHERE identifier=? AND type=3000",
                        ids.certificateSHA256];
  if ([rs next]) {
    [rs close];
    return YES;
  }
  [rs close];

  rs = [db
      executeQuery:@"SELECT * FROM execution_rules WHERE identifier=? AND type=4000", ids.teamID];
  if ([rs next]) {
    [rs close];
    return YES;
  }
  [rs close];

  return NO;
}

static BOOL QueryUnionAll(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs = [db
      executeQuery:@"SELECT * FROM execution_rules WHERE identifier=? AND type=500 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=1000 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=2000 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=3000 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=4000 "
                   @"LIMIT 1",
                   ids.cdhash, ids.binarySHA256, ids.signingID, ids.certificateSHA256, ids.teamID];
  BOOL found = [rs next];
  [rs close];
  return found;
}

static BOOL QueryUnionAllOrderBy(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs = [db
      executeQuery:@"SELECT * FROM ("
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=500 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=1000 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=2000 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=3000 "
                   @"UNION ALL "
                   @"SELECT * FROM execution_rules WHERE identifier=? AND type=4000"
                   @") ORDER BY type ASC LIMIT 1",
                   ids.cdhash, ids.binarySHA256, ids.signingID, ids.certificateSHA256, ids.teamID];
  BOOL found = [rs next];
  [rs close];
  return found;
}

// Demotes transitive rules below every other type by splitting the Binary sub-select on `state`
// and sorting on a constant `prio` per sub-select. Because each prio is a literal, the compound
// query is still naturally ordered and SQLite plans it as a streaming MERGE over indexed lookups
// -- so LIMIT 1 short-circuits and sub-selects after the first match never execute. Costs one
// extra index seek on (binarySHA256, 1000), but only on lookups that get far enough to run it.
static BOOL QueryUnionAllPrio(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs = [db executeQuery:@"SELECT * FROM ("
                                     @"  SELECT 1 AS prio, * FROM execution_rules "
                                     @"    WHERE identifier=? AND type=500 "
                                     @"  UNION ALL "
                                     @"  SELECT 2 AS prio, * FROM execution_rules "
                                     @"    WHERE identifier=? AND type=1000 AND state<>? "
                                     @"  UNION ALL "
                                     @"  SELECT 3 AS prio, * FROM execution_rules "
                                     @"    WHERE identifier=? AND type=2000 "
                                     @"  UNION ALL "
                                     @"  SELECT 4 AS prio, * FROM execution_rules "
                                     @"    WHERE identifier=? AND type=3000 "
                                     @"  UNION ALL "
                                     @"  SELECT 5 AS prio, * FROM execution_rules "
                                     @"    WHERE identifier=? AND type=4000 "
                                     @"  UNION ALL "
                                     @"  SELECT 6 AS prio, * FROM execution_rules "
                                     @"    WHERE identifier=? AND type=1000 AND state=?"
                                     @") ORDER BY prio ASC LIMIT 1",
                                     ids.cdhash, ids.binarySHA256, @(kRuleStateAllowTransitive),
                                     ids.signingID, ids.certificateSHA256, ids.teamID,
                                     ids.binarySHA256, @(kRuleStateAllowTransitive)];
  BOOL found = [rs next];
  [rs close];
  return found;
}

// Same demotion expressed as a CASE over `state` in the ORDER BY, keeping the original five
// sub-selects. Avoids the extra index seek, but the sort key is opaque to the planner: SQLite can
// no longer prove the compound query is ordered, so it materializes the union as a co-routine and
// adds a temp B-tree sort. Included to measure which trade wins.
static BOOL QueryUnionAllCase(FMDatabase* db, const LookupIdentifiers& ids) {
  FMResultSet* rs =
      [db executeQuery:@"SELECT * FROM ("
                       @"SELECT * FROM execution_rules WHERE identifier=? AND type=500 "
                       @"UNION ALL "
                       @"SELECT * FROM execution_rules WHERE identifier=? AND type=1000 "
                       @"UNION ALL "
                       @"SELECT * FROM execution_rules WHERE identifier=? AND type=2000 "
                       @"UNION ALL "
                       @"SELECT * FROM execution_rules WHERE identifier=? AND type=3000 "
                       @"UNION ALL "
                       @"SELECT * FROM execution_rules WHERE identifier=? AND type=4000"
                       @") ORDER BY (CASE WHEN state=? THEN 1000000 ELSE type END) ASC LIMIT 1",
                       ids.cdhash, ids.binarySHA256, ids.signingID, ids.certificateSHA256,
                       ids.teamID, @(kRuleStateAllowTransitive)];
  BOOL found = [rs next];
  [rs close];
  return found;
}

#pragma mark - Benchmark runner

static void RunBenchmark(const Config& config) {
  FMDatabase* db = [FMDatabase databaseWithPath:config.dbPath];
  if (![db open]) {
    std::cerr << "Error: Failed to open database at " << config.dbPath.UTF8String << std::endl;
    exit(1);
  }

  [db setShouldCacheStatements:YES];

  // Pre-build all lookup identifiers before the timed loop. Each iteration gets
  // unique random miss identifiers so we exercise realistic B-tree page access
  // patterns rather than hitting the same cached pages every time.
  std::vector<LookupIdentifiers> lookups;
  lookups.reserve(config.iterations);

  std::mt19937 gen(kSeed);

  if (config.lookup == LookupType::kMixed) {
    LookupType allTypes[] = {
        LookupType::kCDHash,      LookupType::kBinary,   LookupType::kSigningID,
        LookupType::kCertificate, LookupType::kTeamID,   LookupType::kMultiMatch,
        LookupType::kTransitive,  LookupType::kShadowed, LookupType::kMiss,
    };
    std::uniform_int_distribution<> dist(0, (int)(sizeof(allTypes) / sizeof(allTypes[0])) - 1);
    for (int i = 0; i < config.iterations; i++) {
      lookups.push_back(BuildLookup(allTypes[dist(gen)], gen));
    }
  } else {
    for (int i = 0; i < config.iterations; i++) {
      lookups.push_back(BuildLookup(config.lookup, gen));
    }
  }

  // Select strategy
  BOOL (*queryFn)(FMDatabase*, const LookupIdentifiers&) = nullptr;
  switch (config.strategy) {
    case Strategy::kNone: queryFn = QueryNone; break;
    case Strategy::kImplicit: queryFn = QueryImplicit; break;
    case Strategy::kOrderBy: queryFn = QueryOrderBy; break;
    case Strategy::kSeparate: queryFn = QuerySeparate; break;
    case Strategy::kUnionAll: queryFn = QueryUnionAll; break;
    case Strategy::kUnionAllOrderBy: queryFn = QueryUnionAllOrderBy; break;
    case Strategy::kUnionAllPrio: queryFn = QueryUnionAllPrio; break;
    case Strategy::kUnionAllCase: queryFn = QueryUnionAllCase; break;
  }

  int hits = 0;
  for (int i = 0; i < config.iterations; i++) {
    if (queryFn(db, lookups[i])) {
      hits++;
    }
  }

  if (config.verbose) {
    std::cout << "Results: " << hits << " hits out of " << config.iterations << " lookups"
              << std::endl;
  }

  [db close];
}

#pragma mark - CLI

static std::optional<Strategy> ParseStrategy(const char* s) {
  if (strcmp(s, "none") == 0) return Strategy::kNone;
  if (strcmp(s, "implicit") == 0) return Strategy::kImplicit;
  if (strcmp(s, "orderby") == 0) return Strategy::kOrderBy;
  if (strcmp(s, "separate") == 0) return Strategy::kSeparate;
  if (strcmp(s, "unionall") == 0) return Strategy::kUnionAll;
  if (strcmp(s, "unionallorderby") == 0) return Strategy::kUnionAllOrderBy;
  if (strcmp(s, "unionallprio") == 0) return Strategy::kUnionAllPrio;
  if (strcmp(s, "unionallcase") == 0) return Strategy::kUnionAllCase;
  return std::nullopt;
}

static std::optional<LookupType> ParseLookup(const char* s) {
  if (strcmp(s, "cdhash") == 0) return LookupType::kCDHash;
  if (strcmp(s, "binary") == 0) return LookupType::kBinary;
  if (strcmp(s, "signingid") == 0) return LookupType::kSigningID;
  if (strcmp(s, "certificate") == 0) return LookupType::kCertificate;
  if (strcmp(s, "teamid") == 0) return LookupType::kTeamID;
  if (strcmp(s, "multimatch") == 0) return LookupType::kMultiMatch;
  if (strcmp(s, "transitive") == 0) return LookupType::kTransitive;
  if (strcmp(s, "shadowed") == 0) return LookupType::kShadowed;
  if (strcmp(s, "miss") == 0) return LookupType::kMiss;
  if (strcmp(s, "mixed") == 0) return LookupType::kMixed;
  return std::nullopt;
}

static void PrintUsage() {
  std::cout << "Usage: " << getprogname() << " [OPTIONS]\n"
            << "Options:\n"
            << "  -g <count>     Generate database with <count> random rules, then exit\n"
            << "  -i <count>     Number of lookup iterations (default: 1000)\n"
            << "  -t <strategy>  Query strategy: none, implicit, orderby, separate, unionall,\n"
            << "                 unionallorderby, unionallprio, unionallcase\n"
            << "                 (default: implicit)\n"
            << "  -l <lookup>    Lookup type: cdhash, binary, signingid, certificate,\n"
            << "                   teamid, multimatch, transitive, shadowed, miss, mixed\n"
            << "                   (default: mixed)\n"
            << "  -d <path>      Database path (default: /tmp/rule_bench.db)\n"
            << "  -v             Verbose output\n"
            << "  -h             Show this help\n";
}

int main(int argc, char* argv[]) {
  @autoreleasepool {
    Config config;
    int opt;

    while ((opt = getopt(argc, argv, "g:i:t:l:d:vh")) != -1) {
      switch (opt) {
        case 'g': {
          char* end;
          long val = strtol(optarg, &end, 10);
          if (*end != '\0' || val <= 0) {
            std::cerr << "Error: Invalid generate count: " << optarg << std::endl;
            return 1;
          }
          config.generateCount = (int)val;
          break;
        }
        case 'i': {
          char* end;
          long val = strtol(optarg, &end, 10);
          if (*end != '\0' || val <= 0) {
            std::cerr << "Error: Invalid iteration count: " << optarg << std::endl;
            return 1;
          }
          config.iterations = (int)val;
          break;
        }
        case 't': {
          auto s = ParseStrategy(optarg);
          if (!s) {
            std::cerr << "Error: Invalid strategy: " << optarg << std::endl;
            PrintUsage();
            return 1;
          }
          config.strategy = *s;
          break;
        }
        case 'l': {
          auto l = ParseLookup(optarg);
          if (!l) {
            std::cerr << "Error: Invalid lookup type: " << optarg << std::endl;
            PrintUsage();
            return 1;
          }
          config.lookup = *l;
          break;
        }
        case 'd': config.dbPath = [NSString stringWithUTF8String:optarg]; break;
        case 'v': config.verbose = true; break;
        case 'h': PrintUsage(); return 0;
        case '?': PrintUsage(); return 1;
        default: PrintUsage(); return 1;
      }
    }

    if (optind < argc) {
      std::cerr << "Error: Unexpected arguments:";
      for (int i = optind; i < argc; i++) {
        std::cerr << " " << argv[i];
      }
      std::cerr << std::endl;
      PrintUsage();
      return 1;
    }

    if (config.generateCount > 0) {
      GenerateDatabase(config);
      return 0;
    }

    if (![[NSFileManager defaultManager] fileExistsAtPath:config.dbPath]) {
      std::cerr << "Error: Database not found at " << config.dbPath.UTF8String << std::endl;
      std::cerr << "Generate one first with: " << getprogname() << " -g <count>" << std::endl;
      return 1;
    }

    RunBenchmark(config);
    return 0;
  }
}
