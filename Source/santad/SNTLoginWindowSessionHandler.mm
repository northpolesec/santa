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

#import "Source/santad/SNTLoginWindowSessionHandler.h"

#include <errno.h>
#include <pwd.h>
#include <unistd.h>

#include <vector>

@implementation SNTLoginWindowSessionHandler {
  std::shared_ptr<santa::TemporaryAdminMode> _temporaryAdminMode;
  dispatch_queue_t _queue;
}

- (instancetype)initWithTemporaryAdminMode:(std::shared_ptr<santa::TemporaryAdminMode>)tam
                                     queue:(dispatch_queue_t)queue {
  self = [super init];
  if (self) {
    _temporaryAdminMode = std::move(tam);
    _queue = queue;
  }
  return self;
}

- (instancetype)initWithTemporaryAdminMode:(std::shared_ptr<santa::TemporaryAdminMode>)tam {
  return
      [self initWithTemporaryAdminMode:std::move(tam)
                                 queue:dispatch_queue_create_with_target(
                                           "com.northpolesec.santa.lwsession",
                                           DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                           dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0))];
}

- (void)handleLoginWindowSessionEvent:(es_event_type_t)eventType username:(NSString*)username {
  SNTTemporaryAdminModeLeaveReason reason;
  switch (eventType) {
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
      reason = SNTTemporaryAdminModeLeaveReasonScreenLocked;
      break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
      reason = SNTTemporaryAdminModeLeaveReasonSessionEnded;
      break;
    default: return;
  }
  // Guard against an empty/nil username (invalid UTF-8, or the loginwindow pseudo-user).
  if (username.length == 0) {
    return;
  }
  // Resolve the uid and run the revoke (RemoveMember can be a slow OpenDirectory write) off the
  // ES handler thread. `username` is retained by the block; UTF8String is read on the queue.
  auto tam = _temporaryAdminMode;
  dispatch_async(_queue, ^{
    struct passwd pwd;
    struct passwd* result = NULL;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize <= 0) {
      bufsize = 1024;
    }
    std::vector<char> buf(bufsize);
    // getpwnam_r returns ERANGE when the entry doesn't fit; grow and retry so directory-backed
    // (LDAP/AD) entries larger than the initial buffer still resolve. Cap the growth so a
    // pathological entry can't drive unbounded allocation.
    int rc;
    while ((rc = getpwnam_r(username.UTF8String, &pwd, buf.data(), buf.size(), &result)) == ERANGE &&
           buf.size() < (1 << 20)) {
      buf.resize(buf.size() * 2);
    }
    if (rc != 0 || result == NULL || pwd.pw_uid == 0) {
      // Unresolved, or the loginwindow/root pseudo-user — never a TAM target. The timer remains
      // the backstop if a real revoke was somehow missed.
      return;
    }
    tam->EndForUserEvent(pwd.pw_uid, reason);
  });
}

@end
