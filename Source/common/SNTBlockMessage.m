/// Copyright 2016 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/common/SNTBlockMessage.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTFileAccessEvent.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTSystemInfo.h"

static id ValueOrNull(id value) {
  return value ?: [NSNull null];
}

@implementation SNTBlockMessage

+ (NSAttributedString *)formatMessage:(NSString *)message withFallback:(NSString *)fallback {
  if (!message.length) return [[NSAttributedString alloc] initWithString:fallback];

  NSString *htmlHeader = @"<html><head><style>"
                         @"body {"
                         @"  font-family: 'Lucida Grande', 'Helvetica', sans-serif;"
                         @"  font-size: 13px;"
                         @"  text-align: center;"
                         @"}"
                         @"</style></head><body>";
  NSString *htmlFooter = @"</body></html>";
  NSString *fullHTML = [NSString stringWithFormat:@"%@%@%@", htmlHeader, message, htmlFooter];

#ifdef SANTAGUI
  NSData *htmlData = [fullHTML dataUsingEncoding:NSUTF8StringEncoding];
  NSDictionary *options = @{
    NSDocumentTypeDocumentAttribute : NSHTMLTextDocumentType,
    NSCharacterEncodingDocumentAttribute : @(NSUTF8StringEncoding),
  };
  return [[NSAttributedString alloc] initWithHTML:htmlData options:options documentAttributes:NULL];
#else
  NSString *strippedHTML = [self stringFromHTML:fullHTML];
  if (!strippedHTML) {
    return [[NSAttributedString alloc] initWithString:fallback];
  }
  return [[NSAttributedString alloc] initWithString:strippedHTML];
#endif
}

+ (NSAttributedString *)attributedBlockMessageForEvent:(SNTStoredEvent *)event
                                         customMessage:(NSString *)customMessage {
  NSString *defaultBlockedMessage = NSLocalizedString(
    @"The following application has been blocked from executing\nbecause its trustworthiness "
    @"cannot be determined",
    @"The default message to show the user when an unknown application is blocked");
  NSString *defaultBannedMessage =
    NSLocalizedString(@"The following application has been blocked from\nexecuting because it has "
                      @"been deemed malicious",
                      @"The default message to show the user when a banned application is blocked");

  if (customMessage.length) {
    return [self formatMessage:customMessage
                  withFallback:event.decision == SNTEventStateBlockUnknown ? defaultBlockedMessage
                                                                           : defaultBannedMessage];
  } else if (event.decision == SNTEventStateBlockUnknown) {
    return [self formatMessage:[[SNTConfigurator configurator] unknownBlockMessage]
                  withFallback:defaultBlockedMessage];
  }
  return [self formatMessage:[[SNTConfigurator configurator] bannedBlockMessage]
                withFallback:defaultBannedMessage];
}

+ (NSAttributedString *)attributedBlockMessageForFileAccessEvent:(SNTFileAccessEvent *)event
                                                   customMessage:(NSString *)customMessage {
  NSString *defaultBlockedMesage =
    NSLocalizedString(@"Access to a file has been denied",
                      @"The default message to show the user when access to a file is blocked");

  return [SNTBlockMessage
    formatMessage:customMessage ?: [[SNTConfigurator configurator] fileAccessBlockMessage]
     withFallback:defaultBlockedMesage];
}

+ (NSAttributedString *)attributedBlockMessageForDeviceEvent:(SNTDeviceEvent *)event {
  NSString *defaultRemountMessage =
    NSLocalizedString(@"The following device has been remounted with reduced permissions",
                      @"The default message to show the user when a USB device is remounted with "
                      @"reduced permissions");
  NSString *defaultBannedMessage = NSLocalizedString(
    @"The following device has been blocked from mounting",
    @"The default message to show the user when a USB device is blocked from mounting");

  if ([[SNTConfigurator configurator] remountUSBMode]) {
    return [SNTBlockMessage formatMessage:[[SNTConfigurator configurator] remountUSBBlockMessage]
                             withFallback:defaultRemountMessage];
  }
  return [SNTBlockMessage formatMessage:[[SNTConfigurator configurator] bannedUSBBlockMessage]
                           withFallback:defaultBannedMessage];
}

+ (NSString *)stringFromHTML:(NSString *)html {
  NSError *error;
  NSXMLDocument *xml = [[NSXMLDocument alloc]
    initWithXMLString:html
              options:NSXMLDocumentIncludeContentTypeDeclaration | NSXMLNodeCompactEmptyElement |
                      NSXMLNodeLoadExternalEntitiesNever | NSXMLNodeNeverEscapeContents
                error:&error];

  if (error) {
    return nil;
  }

  // Strip any HTML tags out of the message. Also remove any content inside <style> tags and
  // replace <br> elements with a newline.
  NSString *stripXslt =
    @"<?xml version='1.0' encoding='utf-8'?>"
    @"<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'"
    @"                              xmlns:xhtml='http://www.w3.org/1999/xhtml'>"
    @"<xsl:output method='text'/>"
    @"<xsl:template match='br'><xsl:text>\n</xsl:text></xsl:template>"
    @"<xsl:template match='style'/>"
    @"</xsl:stylesheet>";
  NSData *data = [xml objectByApplyingXSLTString:stripXslt arguments:NULL error:&error];
  if (error || ![data isKindOfClass:[NSData class]]) {
    return nil;
  }
  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSString *)replaceFormatString:(NSString *)str
                         withDict:(NSDictionary<NSString *, NSString *> *)replacements {
  __block NSString *formatStr = str;

  [replacements enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
    if ((id)value != [NSNull null]) {
      formatStr = [formatStr stringByReplacingOccurrencesOfString:key withString:value];
    }
  }];

  return formatStr;
}

//
//   The following "format strings" will be replaced in the URL provided by
//   `+eventDetailURLForEvent:customURL:templateMapping:`.
//
//   %file_identifier%           - The SHA-256 of the binary being executed.
//   %bundle_or_file_identifier% - The hash of the bundle containing this file or the file itself,
//                                 if no bundle hash is present.
//   %file_bundle_id%            - The bundle id of the binary, if any.
//   %team_id%                   - The Team ID if present in the signature information.
//   %signing_id%                - The Signing ID if present in the signature information.
//   %cdhash%                    - If signed, the CDHash.
//   %username%                  - The executing user's name.
//   %machine_id%                - The configured machine ID for this host.
//   %hostname%                  - The machine's FQDN.
//   %uuid%                      - The machine's UUID.
//   %serial%                    - The machine's serial number.
//
+ (NSDictionary *)eventDetailTemplateMappingForEvent:(SNTStoredEvent *)event {
  SNTConfigurator *config = [SNTConfigurator configurator];
  return @{
    @"%file_sha%" : ValueOrNull(event.fileSHA256 ? event.fileBundleHash ?: event.fileSHA256 : nil),
    @"%file_identifier%" : ValueOrNull(event.fileSHA256),
    @"%bundle_or_file_identifier%" :
      ValueOrNull(event.fileSHA256 ? event.fileBundleHash ?: event.fileSHA256 : nil),
    @"%username%" : ValueOrNull(event.executingUser),
    @"%file_bundle_id%" : ValueOrNull(event.fileBundleID),
    @"%team_id%" : ValueOrNull(event.teamID),
    @"%signing_id%" : ValueOrNull(event.signingID),
    @"%cdhash%" : ValueOrNull(event.cdhash),
    @"%machine_id%" : ValueOrNull(config.machineID),
    @"%hostname%" : ValueOrNull([SNTSystemInfo longHostname]),
    @"%uuid%" : ValueOrNull([SNTSystemInfo hardwareUUID]),
    @"%serial%" : ValueOrNull([SNTSystemInfo serialNumber]),
  };
}

//
//   Everything from `+eventDetailTemplateMappingForEvent:` with the following file access
//   specific templates.
//
//   %rule_version%    - The version of the rule that was violated.
//   %rule_name%       - The name of the rule that was violated.
//   %accessed_path%   - The path accessed by the binary.
//
+ (NSDictionary *)fileAccessEventDetailTemplateMappingForEvent:(SNTFileAccessEvent *)event {
  NSMutableDictionary *d = [self eventDetailTemplateMappingForEvent:event].mutableCopy;
  [d addEntriesFromDictionary:@{
    @"%rule_version%" : ValueOrNull(event.ruleVersion),
    @"%rule_name%" : ValueOrNull(event.ruleName),
    @"%accessed_path%" : ValueOrNull(event.accessedPath),
  }];
  return d;
}

// Returns either the generated URL for the passed in event, or an NSURL from the passed in custom
// URL string. If the custom URL string is the string "null", nil will be returned. If no custom
// URL is passed and there is no configured EventDetailURL template, nil will be returned.
// The "format strings" in `templateMapping` will be replaced in the URL, if they are present.
+ (NSURL *)eventDetailURLForEvent:(SNTStoredEvent *)event
                        customURL:(NSString *)url
                  templateMapping:(NSDictionary *)templateMapping {
  SNTConfigurator *config = [SNTConfigurator configurator];

  NSString *formatStr = url;
  if (!formatStr.length) {
    formatStr = config.eventDetailURL;
    if (!formatStr.length) {
      return nil;
    }
  }

  if ([formatStr isEqualToString:@"null"]) {
    return nil;
  }

  formatStr = [SNTBlockMessage replaceFormatString:formatStr withDict:templateMapping];
  NSURL *u = [NSURL URLWithString:formatStr];
  if (!u) {
    LOGW(@"Unable to generate event detail URL for string '%@'", formatStr);
  }

  return u;
}

+ (NSURL *)eventDetailURLForEvent:(SNTStoredEvent *)event customURL:(NSString *)url {
  return [self eventDetailURLForEvent:event
                            customURL:url
                      templateMapping:[self eventDetailTemplateMappingForEvent:event]];
}

+ (NSURL *)eventDetailURLForFileAccessEvent:(SNTFileAccessEvent *)event customURL:(NSString *)url {
  return [self eventDetailURLForEvent:event
                            customURL:url
                      templateMapping:[self fileAccessEventDetailTemplateMappingForEvent:event]];
}

@end
