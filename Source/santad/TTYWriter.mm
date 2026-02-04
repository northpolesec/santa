/// Copyright 2023 Google LLC
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

#include "Source/santad/TTYWriter.h"

#include <signal.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"

namespace santa {

std::unique_ptr<TTYWriter> TTYWriter::Create(bool silent_tty_mode) {
  dispatch_queue_t q = dispatch_queue_create_with_target(
      "com.northpolesec.santa.ttywriter", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));

  if (!q) {
    LOGW(@"Unable to create dispatch queue for TTYWriter");
    return nullptr;
  }

  return std::make_unique<TTYWriter>(q, silent_tty_mode);
}

TTYWriter::TTYWriter(dispatch_queue_t q, bool silent_tty_mode)
    : q_(q), silent_tty_mode_(silent_tty_mode) {}

bool TTYWriter::CanWrite(const es_process_t *proc) {
  return proc && proc->tty && proc->tty->path.length > 0;
}

void TTYWriter::Write(const es_process_t *proc, bool send_signal,
                      NSString * (^messageCreator)(void)) {
  if (silent_tty_mode_.load(std::memory_order_relaxed) || !CanWrite(proc)) {
    return;
  }

  // Copy the data from the es_process_t so the ES message doesn't
  // need to be retained
  NSString *tty = santa::StringToNSString(proc->tty->path.data);
  // Realize the message string before going async so as not to need to worry about
  // lifetimes of objects in the provided block.
  NSString *msg = messageCreator();
  NSString *companyName = [[SNTConfigurator configurator] brandingCompanyName];
  if (companyName) {
    msg = [msg stringByAppendingFormat:@"\nManaged by: %@\n", companyName];
  }
  msg = [msg stringByAppendingFormat:@"\n"];

  dispatch_async(q_, ^{
    int fd = open(tty.UTF8String, O_WRONLY | O_NOCTTY);
    if (fd == -1) {
      LOGW(@"Failed to open TTY for writing: %s", strerror(errno));
      return;
    }

    std::string_view str = santa::NSStringToUTF8StringView(msg);
    write(fd, str.data(), str.length());

    // Send SIGWINCH to the foreground process group to trigger a shell prompt redraw.
    // Without this, the prompt gets "buried" above our message because the shell
    // redraws its prompt when the blocked process exits, but our async write
    // happens after that.
    pid_t pgrp = 0;
    if (send_signal) {
      ioctl(fd, TIOCGPGRP, &pgrp);
    }

    close(fd);

    if (send_signal && pgrp > 1) {
      kill(-pgrp, SIGWINCH);
    }
  });
}

void TTYWriter::Write(const es_process_t *proc, NSString * (^messageCreator)(void)) {
  Write(proc, true, messageCreator);
}

void TTYWriter::Write(const es_process_t *proc, NSString *msg) {
  Write(proc, true, ^NSString * {
    return msg;
  });
}

void TTYWriter::WriteWithoutSignal(const es_process_t *proc, NSString *msg) {
  Write(proc, false, ^NSString * {
    return msg;
  });
}

void TTYWriter::EnableSilentTTYMode(bool silent_tty_mode) {
  silent_tty_mode_.store(silent_tty_mode, std::memory_order_relaxed);
}

}  // namespace santa
