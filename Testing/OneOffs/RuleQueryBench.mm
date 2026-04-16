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
  STRATEGIES=implicit,orderby,separate,unionall,unionallorderby
  LOOKUPS=cdhash,teamid,miss,multimatch,mixed
  /opt/homebrew/bin/hyperfine --warmup 10 \
      --parameter-list strategy $STRATEGIES \
      --parameter-list lookup $LOOKUPS \
      "$BENCH -i 10000 -t {strategy} -l {lookup} -d /tmp/rule_bench.db"

Strategies:
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
                    This is the strategy used in production (see SNTRuleTable.mm).

Lookup types:
  cdhash      - Hit on CDHash rule (highest priority, best case for short-circuit)
  binary      - Hit on Binary rule
  signingid   - Hit on SigningID rule
  certificate - Hit on Certificate rule
  teamid      - Hit on TeamID rule (lowest priority, worst case for short-circuit)
  multimatch  - Hits on SigningID + Certificate + TeamID simultaneously (tests ordering correctness)
  miss        - No matching rule exists
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

#pragma mark - Enums and config

enum class Strategy {
  kImplicit,
  kOrderBy,
  kSeparate,
  kUnionAll,
  kUnionAllOrderBy,
};

enum class LookupType {
  kCDHash,
  kBinary,
  kSigningID,
  kCertificate,
  kTeamID,
  kMultiMatch,
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

static NSString* RandomHex(int length, std::mt19937& gen) {
  static const char hex[] = "0123456789abcdef";
  std::uniform_int_distribution<> dist(0, 15);
  NSMutableString* s = [NSMutableString stringWithCapacity:length];
  for (int i = 0; i < length; i++) {
    [s appendFormat:@"%c", hex[dist(gen)]];
  }
  return s;
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
  return
      [NSString stringWithFormat:@"%@:com.example.bench.%@", RandomTeamID(gen), RandomHex(8, gen)];
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

    [db executeUpdate:
            @"INSERT OR IGNORE INTO execution_rules (identifier, state, type) VALUES (?, ?, ?)",
            identifier, @(kRuleStateAllow), @(type)];

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
    case LookupType::kMiss: break;
    case LookupType::kMixed: break;  // handled by caller
  }
  return ids;
}

#pragma mark - Query strategies

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
    std::uniform_int_distribution<> dist(0, 6);
    LookupType allTypes[] = {
        LookupType::kCDHash,      LookupType::kBinary, LookupType::kSigningID,
        LookupType::kCertificate, LookupType::kTeamID, LookupType::kMultiMatch,
        LookupType::kMiss,
    };
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
    case Strategy::kImplicit: queryFn = QueryImplicit; break;
    case Strategy::kOrderBy: queryFn = QueryOrderBy; break;
    case Strategy::kSeparate: queryFn = QuerySeparate; break;
    case Strategy::kUnionAll: queryFn = QueryUnionAll; break;
    case Strategy::kUnionAllOrderBy: queryFn = QueryUnionAllOrderBy; break;
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
  if (strcmp(s, "implicit") == 0) return Strategy::kImplicit;
  if (strcmp(s, "orderby") == 0) return Strategy::kOrderBy;
  if (strcmp(s, "separate") == 0) return Strategy::kSeparate;
  if (strcmp(s, "unionall") == 0) return Strategy::kUnionAll;
  if (strcmp(s, "unionallorderby") == 0) return Strategy::kUnionAllOrderBy;
  return std::nullopt;
}

static std::optional<LookupType> ParseLookup(const char* s) {
  if (strcmp(s, "cdhash") == 0) return LookupType::kCDHash;
  if (strcmp(s, "binary") == 0) return LookupType::kBinary;
  if (strcmp(s, "signingid") == 0) return LookupType::kSigningID;
  if (strcmp(s, "certificate") == 0) return LookupType::kCertificate;
  if (strcmp(s, "teamid") == 0) return LookupType::kTeamID;
  if (strcmp(s, "multimatch") == 0) return LookupType::kMultiMatch;
  if (strcmp(s, "miss") == 0) return LookupType::kMiss;
  if (strcmp(s, "mixed") == 0) return LookupType::kMixed;
  return std::nullopt;
}

static void PrintUsage() {
  std::cout << "Usage: " << getprogname() << " [OPTIONS]\n"
            << "Options:\n"
            << "  -g <count>     Generate database with <count> random rules, then exit\n"
            << "  -i <count>     Number of lookup iterations (default: 1000)\n"
            << "  -t <strategy>  Query strategy: implicit, orderby, separate, unionall,\n"
            << "                 unionallorderby (default: implicit)\n"
            << "  -l <lookup>    Lookup type: cdhash, binary, signingid, certificate,\n"
            << "                   teamid, multimatch, miss, mixed (default: mixed)\n"
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
