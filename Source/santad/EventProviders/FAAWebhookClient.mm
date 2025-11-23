/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/santad/EventProviders/FAAWebhookClient.h"

#import <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <pwd.h>
#include <string>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/String.h"

namespace santa {

FAAWebhookClient::FAAWebhookClient() {
  queue_ = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
  NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
  config.timeoutIntervalForRequest = 10.0;  // 10 second timeout
  config.timeoutIntervalForResource = 30.0;
  url_session_ = [NSURLSession sessionWithConfiguration:config];
}

FAAWebhookClient::~FAAWebhookClient() {
  // Invalidate and cancel the session to cancel any pending tasks
  // This ensures the object outlives any async operations
  if (url_session_) {
    [url_session_ invalidateAndCancel];
    url_session_ = nil;
  }
}

void FAAWebhookClient::TriggerWebhookForRuleMatch(const WatchItemPolicyBase &policy,
                                                  const std::string &target_path,
                                                  const Message &msg) {
  // Check if webhook is configured
  if (!policy.webhook_url.has_value() || !policy.webhook_url.value()) {
    return;
  }

  NSString *webhook_url_template = policy.webhook_url.value();
  NSDictionary *webhook_headers = policy.webhook_headers.has_value()
                                      ? policy.webhook_headers.value()
                                      : nil;

  // Create a copy of necessary data before going async
  std::string policy_name_copy = policy.name;
  std::string policy_version_copy = policy.version;
  std::string target_path_copy = target_path;
  Message msg_copy = msg;

  // Capture url_session_ explicitly to avoid accessing 'this' in the async block
  // This ensures the NSURLSession is retained even if FAAWebhookClient is destroyed
  NSURLSession *session = url_session_;

  dispatch_async(queue_, ^{
    // Build the event for template mapping
    // We need to create a minimal event with the information we have
    SNTCachedDecision *cd = [[SNTDecisionCache sharedCache]
        cachedDecisionForFile:msg_copy->process->executable->stat];
    SNTStoredFileAccessEvent *event = [[SNTStoredFileAccessEvent alloc] init];

    event.accessedPath = StringToNSString(target_path_copy);
    event.ruleVersion = StringToNSString(policy_version_copy);
    event.ruleName = StringToNSString(policy_name_copy);
    event.process.fileSHA256 = cd.sha256 ?: @"<unknown sha>";
    event.process.filePath = StringToNSString(msg_copy->process->executable->path.data);
    event.process.teamID = cd.teamID ?: @"<unknown team id>";
    event.process.signingID = cd.signingID ?: @"<unknown signing id>";
    event.process.cdhash = cd.cdhash ?: @"<unknown CDHash>";
    event.process.pid = @(audit_token_to_pid(msg_copy->process->audit_token));
    event.process.signingChain = cd.certChain;
    struct passwd *user = getpwuid(audit_token_to_ruid(msg_copy->process->audit_token));
    if (user) event.process.executingUser = @(user->pw_name);
    event.process.parent = [[SNTStoredFileAccessProcess alloc] init];
    event.process.parent.pid = @(audit_token_to_pid(msg_copy->process->parent_audit_token));
    event.process.parent.filePath = StringToNSString(msg_copy.ParentProcessPath());

    // Build the URL with variable substitution (using static helper to avoid accessing 'this')
    NSURL *url = [SNTBlockMessage eventDetailURLForFileAccessEvent:event
                                                         customURL:webhook_url_template];
    if (!url) {
      NSString *rule_name = StringToNSString(policy_name_copy);
      LOGW(@"Failed to build webhook URL for rule '%@'", rule_name);
      return;
    }

    // Create the request (inline to avoid accessing 'this')
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    // Add custom headers if provided
    if (webhook_headers) {
      for (NSString *key in webhook_headers) {
        id value = webhook_headers[key];
        if ([value isKindOfClass:[NSString class]]) {
          [request setValue:(NSString *)value forHTTPHeaderField:key];
        }
      }
    }

    // Perform the request asynchronously using the captured session
    // Convert rule name to NSString inside the completion handler to avoid use-after-free
    // The policy_name_copy std::string is captured by the dispatch_async block and will
    // remain valid until the block completes
    NSURLSessionDataTask *task = [session
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            // Convert string inside completion handler to ensure it's valid when used
            NSString *rule_name = StringToNSString(policy_name_copy);
            if (error) {
              LOGW(@"Webhook request failed for rule '%@': %@", rule_name,
                   error.localizedDescription);
              return;
            }

            if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
              NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
              if (httpResponse.statusCode >= 200 && httpResponse.statusCode < 300) {
                LOGD(@"Webhook request succeeded for rule '%@' (status: %ld)",
                     rule_name, (long)httpResponse.statusCode);
              } else {
                LOGW(@"Webhook request returned error status for rule '%@': %ld",
                     rule_name, (long)httpResponse.statusCode);
              }
            }
          }];

    [task resume];
  });
}

}  // namespace santa

