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

#import "Source/santasyncservice/SNTSyncPublishMetrics.h"
#include "Source/common/String.h"

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include "syncv2/v2.pb.h"

using ::santa::sync::v2::PublishMetricsRequest;
using ::santa::sync::v2::PublishMetricsResponse;
using Metric = ::santa::sync::v2::PublishMetricsRequest_Metric;
using Value = ::santa::sync::v2::PublishMetricsRequest_Metric_Value;

namespace {

Metric::MetricKind MetricKindForType(SNTMetricType type) {
  switch (type) {
    case SNTMetricTypeConstantBool:
    case SNTMetricTypeConstantString:
    case SNTMetricTypeConstantInt64:
    case SNTMetricTypeConstantDouble: return Metric::MetricKind_CONSTANT;
    case SNTMetricTypeGaugeBool:
    case SNTMetricTypeGaugeString:
    case SNTMetricTypeGaugeInt64:
    case SNTMetricTypeGaugeDouble: return Metric::MetricKind_GAUGE;
    case SNTMetricTypeCounter: return Metric::MetricKind_COUNTER;
    default: return Metric::MetricKind_UNKNOWN;
  }
}

void SetMetricValue(Value *value, id data, SNTMetricType type) {
  switch (type) {
    case SNTMetricTypeConstantBool:
    case SNTMetricTypeGaugeBool: value->set_bool_([data boolValue]); break;
    case SNTMetricTypeConstantInt64:
    case SNTMetricTypeGaugeInt64:
    case SNTMetricTypeCounter: value->set_int64([data longLongValue]); break;
    case SNTMetricTypeConstantDouble:
    case SNTMetricTypeGaugeDouble: value->set_double_([data doubleValue]); break;
    case SNTMetricTypeConstantString:
    case SNTMetricTypeGaugeString: value->set_string(santa::NSStringToUTF8StringView(data)); break;
    default: LOGE(@"Unknown SNTMetricType %d", (int)type); break;
  }
}

void PopulateRequest(PublishMetricsRequest *request, NSDictionary *metrics) {
  for (NSString *metricName in metrics[@"metrics"]) {
    NSDictionary *metric = metrics[@"metrics"][metricName];

    Metric *protoMetric = request->add_metrics();
    protoMetric->set_path(santa::NSStringToUTF8StringView(metricName));

    SNTMetricType type = static_cast<SNTMetricType>([metric[@"type"] integerValue]);
    protoMetric->set_kind(MetricKindForType(type));

    for (NSString *fieldName in metric[@"fields"]) {
      for (NSDictionary *entry in metric[@"fields"][fieldName]) {
        if (![fieldName isEqualToString:@""]) {
          NSArray<NSString *> *fieldNames = [fieldName componentsSeparatedByString:@","];
          NSArray<NSString *> *fieldValues = [entry[@"value"] componentsSeparatedByString:@","];

          if (fieldNames.count != fieldValues.count) {
            LOGE(@"Malformed metric data: %@", fieldName);
            continue;
          }

          Value *value = protoMetric->add_values();
          for (NSUInteger i = 0; i < fieldNames.count; i++) {
            NSString *v = [NSString stringWithFormat:@"%@=%@", fieldNames[i], fieldValues[i]];
            value->add_fields(santa::NSStringToUTF8StringView(v));
          }
          SetMetricValue(value, entry[@"data"], type);
        } else {
          Value *value = protoMetric->add_values();
          SetMetricValue(value, entry[@"data"], type);
        }
      }
    }
  }

  for (NSString *key in metrics[@"root_labels"]) {
    NSString *value = metrics[@"root_labels"][key];
    (*request->mutable_root_labels())[santa::NSStringToUTF8StringView(key)] =
        santa::NSStringToUTF8StringView(value);
  }
}

}  // namespace

@implementation SNTSyncPublishMetrics

- (NSURL *)stageURL {
  NSString *stageName = [@"metrics" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

// Not used; this stage is invoked directly via publishMetrics: rather than the standard sync flow.
- (BOOL)sync {
  return NO;
}

- (BOOL)publishMetrics:(NSDictionary *)metrics {
  PublishMetricsRequest request;
  request.set_machine_id(santa::NSStringToUTF8StringView(self.syncState.machineID));
  PopulateRequest(&request, metrics);

  NSMutableURLRequest *req = [self requestWithMessage:&request];
  if (!req) {
    SLOGE(@"Failed to create publish metrics request");
    return NO;
  }

  PublishMetricsResponse response;
  NSError *error = [self performRequest:req intoMessage:&response timeout:30];
  if (error) {
    SLOGE(@"Publish metrics failed: %@", error.localizedDescription);
    return NO;
  }

  return YES;
}

@end
