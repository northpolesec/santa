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

#import "Source/common/SNTRuleTimeWindow.h"

#import "Source/common/CoderMacros.h"

// Strict "HH:MM": exactly five characters, four digits and a colon, hour and
// minute in range. Same acceptance rule as the CEL layer's ParseHourMinute,
// re-stated here because that header lives in the cel-cpp-heavy :CEL target
// and this class links into santactl and the GUI.
static BOOL ParseHHMM(NSString* hhmm, int* hour, int* minute) {
  if (hhmm.length != 5 || [hhmm characterAtIndex:2] != ':') {
    return NO;
  }
  unichar c[5];
  [hhmm getCharacters:c range:NSMakeRange(0, 5)];
  const int digitPositions[] = {0, 1, 3, 4};
  for (int index : digitPositions) {
    if (c[index] < '0' || c[index] > '9') {
      return NO;
    }
  }
  *hour = (c[0] - '0') * 10 + (c[1] - '0');
  *minute = (c[3] - '0') * 10 + (c[4] - '0');
  return *hour <= 23 && *minute <= 59;
}

static NSString* JoinRange(NSString* start, NSString* end) {
  return [NSString
      stringWithFormat:NSLocalizedString(@"%@ to %@", @"Two ends of a time range"), start, end];
}

// Renders "HH:MM" as a locale short time without converting the instant: the
// reading is in the rule's zone and the zone suffix carries that meaning.
// Anything ParseHHMM rejects displays as written.
static NSString* TimeReading(NSString* hhmm, NSDateFormatter* tf, NSCalendar* cal) {
  int hour, minute;
  if (!ParseHHMM(hhmm, &hour, &minute)) {
    return hhmm;
  }
  NSDateComponents* components = [[NSDateComponents alloc] init];
  components.year = 2001;
  components.month = 1;
  components.day = 1;
  components.hour = hour;
  components.minute = minute;
  NSDate* date = [cal dateFromComponents:components];
  return date ? [tf stringFromDate:date] : hhmm;
}

// Sorted, de-duplicated, and limited to 0 through 6: the day numbers come from
// a rule, and any other value would index past the weekday symbols.
static NSIndexSet* NormalizedDays(NSArray<NSNumber*>* days) {
  NSMutableIndexSet* normalized = [NSMutableIndexSet indexSet];
  for (NSNumber* day in days) {
    NSInteger value = day.integerValue;
    if (value >= 0 && value <= 6) {
      [normalized addIndex:(NSUInteger)value];
    }
  }
  return normalized;
}

// A gapless run of two or more days reads as a range; anything else, a set that
// wraps past Saturday included, reads as a list.
static NSString* DaysReading(NSIndexSet* days, NSArray<NSString*>* symbols) {
  if (days.count > 1 && days.lastIndex - days.firstIndex + 1 == days.count) {
    return JoinRange(symbols[days.firstIndex], symbols[days.lastIndex]);
  }
  NSMutableArray<NSString*>* names = [NSMutableArray array];
  [days enumerateIndexesUsingBlock:^(NSUInteger day, BOOL* stop) {
    [names addObject:symbols[day]];
  }];
  return [names componentsJoinedByString:@", "];
}

@implementation SNTRuleTimeWindow

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, days);
  ENCODE(coder, startOfDay);
  ENCODE(coder, endOfDay);
  ENCODE(coder, zoneName);
  ENCODE(coder, startDate);
  ENCODE(coder, endDate);
  ENCODE_BOXABLE(coder, open);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE_ARRAY(decoder, days, NSNumber);
    DECODE(decoder, startOfDay, NSString);
    DECODE(decoder, endOfDay, NSString);
    DECODE(decoder, zoneName, NSString);
    DECODE(decoder, startDate, NSDate);
    DECODE(decoder, endDate, NSDate);
    DECODE_SELECTOR(decoder, open, NSNumber, boolValue);
  }
  return self;
}

- (NSString*)displayString {
  return [self displayStringWithLocale:[NSLocale currentLocale]];
}

- (NSString*)displayStringWithLocale:(NSLocale*)locale {
  if (self.startDate && self.endDate) {
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    formatter.locale = locale;
    formatter.dateStyle = NSDateFormatterMediumStyle;
    formatter.timeStyle = NSDateFormatterShortStyle;
    return JoinRange([formatter stringFromDate:self.startDate],
                     [formatter stringFromDate:self.endDate]);
  }

  if (!self.startOfDay || !self.endOfDay) {
    return @"";
  }

  // Components and formatter share one fixed zone so an HH:MM reading comes
  // back unshifted whatever zone the reader is in.
  NSCalendar* calendar =
      [[NSCalendar alloc] initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
  calendar.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
  NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
  formatter.locale = locale;
  formatter.dateStyle = NSDateFormatterNoStyle;
  formatter.timeStyle = NSDateFormatterShortStyle;
  formatter.timeZone = calendar.timeZone;

  NSMutableString* display =
      [JoinRange(TimeReading(self.startOfDay, formatter, calendar),
                 TimeReading(self.endOfDay, formatter, calendar)) mutableCopy];

  NSIndexSet* days = NormalizedDays(self.days);
  if (days.count == 7) {
    [display appendFormat:@" %@", NSLocalizedString(@"every day", @"All seven days")];
  } else if (days.count > 0) {
    [display appendFormat:@", %@", DaysReading(days, formatter.shortWeekdaySymbols)];
  }

  if (self.zoneName.length && ![self.zoneName isEqualToString:@"local"]) {
    [display appendFormat:@" (%@)", self.zoneName];
  }

  return display;
}

@end
