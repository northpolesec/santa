/// Copyright 2023 Google LLC
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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTSystemInfo.h"

@interface SNTBlockMessageTest : XCTestCase
@property id mockConfigurator;
@property id mockSystemInfo;
@end

@implementation SNTBlockMessageTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator machineID]).andReturn(@"my_mid");

  self.mockSystemInfo = OCMClassMock([SNTSystemInfo class]);
  OCMStub([self.mockSystemInfo longHostname]).andReturn(@"my_hn");
  OCMStub([self.mockSystemInfo hardwareUUID]).andReturn(@"my_u");
  OCMStub([self.mockSystemInfo serialNumber]).andReturn(@"my_s");
}

- (void)testFormatMessage {
  NSString *input = @"Testing with somé Ünicode çharacters";
  NSAttributedString *got = [SNTBlockMessage formatMessage:input withFallback:@""];
  XCTAssertEqualObjects([got string], input);
}

- (void)testEventDetailURLForEvent {
  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];

  se.fileSHA256 = @"my_fi";
  se.executingUser = @"my_un";
  se.fileBundleID = @"s.n.t";
  se.cdhash = @"abc";
  se.teamID = @"SNT";
  se.signingID = @"SNT:s.n.t";

  NSString *url = @"http://"
                  @"localhost?fs=%file_sha%&fi=%file_identifier%&bfi=%bundle_or_file_identifier%&"
                  @"fbid=%file_bundle_id%&ti=%team_id%&si=%signing_id%&ch=%cdhash%&"
                  @"un=%username%&mid=%machine_id%&hn=%hostname%&u=%uuid%&s=%serial%";
  NSString *wantUrl = @"http://"
                      @"localhost?fs=my_fi&fi=my_fi&bfi=my_fi&"
                      @"fbid=s.n.t&ti=SNT&si=SNT:s.n.t&ch=abc&"
                      @"un=my_un&mid=my_mid&hn=my_hn&u=my_u&s=my_s";

  NSURL *gotUrl = [SNTBlockMessage eventDetailURLForEvent:se customURL:url];

  // Set fileBundleHash and test again for newly expected values
  se.fileBundleHash = @"my_fbh";

  wantUrl = @"http://"
            @"localhost?fs=my_fbh&fi=my_fi&bfi=my_fbh&"
            @"fbid=s.n.t&ti=SNT&si=SNT:s.n.t&ch=abc&"
            @"un=my_un&mid=my_mid&hn=my_hn&u=my_u&s=my_s";

  gotUrl = [SNTBlockMessage eventDetailURLForEvent:se customURL:url];

  XCTAssertEqualObjects(gotUrl.absoluteString, wantUrl);

  XCTAssertNil([SNTBlockMessage eventDetailURLForEvent:se customURL:nil]);
  XCTAssertNil([SNTBlockMessage eventDetailURLForEvent:se customURL:@"null"]);
}

- (void)testEventDetailURLForFileAccessEvent {
  SNTStoredFileAccessEvent *fae = [[SNTStoredFileAccessEvent alloc] init];

  fae.ruleVersion = @"my_rv";
  fae.ruleName = @"my_rn";
  fae.process.fileSHA256 = @"my_fi";
  fae.process.cdhash = @"abc";
  fae.process.teamID = @"SNT";
  fae.process.signingID = @"SNT:s.n.t";
  fae.accessedPath = @"my_ap";
  fae.process.executingUser = @"my_un";

  NSString *url =
      @"http://"
      @"localhost?rv=%rule_version%&rn=%rule_name%&fi=%file_identifier%&"
      @"ti=%team_id%&si=%signing_id%&ch=%cdhash%&"
      @"ap=%accessed_path%&un=%username%&mid=%machine_id%&hn=%hostname%&u=%uuid%&s=%serial%";
  NSString *wantUrl = @"http://"
                      @"localhost?rv=my_rv&rn=my_rn&fi=my_fi&"
                      @"ti=SNT&si=SNT:s.n.t&ch=abc&"
                      @"ap=my_ap&un=my_un&mid=my_mid&hn=my_hn&u=my_u&s=my_s";

  NSURL *gotUrl = [SNTBlockMessage eventDetailURLForFileAccessEvent:fae customURL:url];

  XCTAssertEqualObjects(gotUrl.absoluteString, wantUrl);

  XCTAssertNil([SNTBlockMessage eventDetailURLForFileAccessEvent:fae customURL:nil]);
  XCTAssertNil([SNTBlockMessage eventDetailURLForFileAccessEvent:fae customURL:@"null"]);
}

- (void)testEventDetailURLMissingDetails {
  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];

  se.fileSHA256 = @"my_fi";

  NSString *url = @"http://localhost?fi=%file_identifier%";
  NSString *wantUrl = @"http://localhost?fi=my_fi";

  NSURL *gotUrl = [SNTBlockMessage eventDetailURLForEvent:se customURL:url];

  XCTAssertEqualObjects(gotUrl.absoluteString, wantUrl);
}

- (void)testStringFromHTML {
  NSString *html = @"<html><body>Hello, world!</body></html>";
  NSString *got = [SNTBlockMessage stringFromHTML:html];
  XCTAssertEqualObjects(got, @"Hello, world!");

  html = @"Entering Lockdown Mode";
  got = [SNTBlockMessage stringFromHTML:html];
  XCTAssertEqualObjects(got, @"Entering Lockdown Mode");

  html = @"Entering Monitoring Mode<br />Please be careful!";
  got = [SNTBlockMessage stringFromHTML:html];
  XCTAssertEqualObjects(got, @"Entering Monitoring Mode\nPlease be careful!");

  html =
      @"This was a a triumph <img "
      @"src='data:image/"
      @"png;base64,"
      @"iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAcNElEQVR4nOydTXAU19X3z22N4rcqUFZ2FllEWSCWHpC"
      @"cRRaWWGUBLuSqVAUMVcBCmJ2NDVsksUoVQcaVjYFKGS8I2iEbWCN5lQoz8niJsvB4A1nKgXqfJ2am71OnP6TRqO+"
      @"d7p7uvt3nnl+VSrYkpKtRn//"
      @"5uOeeWwOm0sh6fQxGRyfAdSdAyjFwnPD9myDlhP9FwXtEiAn9N5Ttnq9tb7933Z9AiC1w3TY4Ttv779ev26LV2srtl2"
      @"NyR5heADOYbSPvdusgRD0w7rpn2EKMmV2c3AqEAt++"
      @"BylbKA6i0Vgzui4mFiwAJcMz9loNjfttcJw6uO7sQK9dXlqeMEi5BkJ8D51OiyOGcsECYBjP4B1nzvPsQswAQN30mnK"
      @"mBVKuA8AadLsoCG3TC7IZFoCC6fHwcwBwosLePStaXtoA8DV0u2scIRQLC0ABeEY/"
      @"MnIWhJjzcnfTeXu5WQMp70K3u87RQf6wAORE4Ok/"
      @"AoDZ4I1JDorBKnS7X7MY5AMLQIbs8vRs9FnDkUEOsABkgJyeRmNf4PC+IFAIAL4Wzeaq6aVUHRaAlGyH+FJ+"
      @"zEZvCCnb4Dg34fVrThFSwgKQkMDbY24/"
      @"Z3otTA8YFQjxFTcgJYMFICbbYT7n9mXHqxWIZvMr0wupAiwAA5BHjpwDIRZ4v75i+"
      @"GcaFlkI9LAAKGDDJwILgRYWgD7Y8InCQhAJC0AA5/iWwEKwC+sFQNbrdajVPmPDt45V6HQu2b59aK0ABPv46PE/"
      @"Nr0WxiB+d+GSrUJgpQDId975CFx3kRt4GA+L0wKrBIDDfUYLCkG3e9SmaMAxvYCikNPTC1CrfcfGzygRYgJqtR+"
      @"8Z8USyEcAgdf/0oJJO0yWWBINkI4Aerw+Gz+TDEuiAZIRgKzX8Y/"
      @"3gA2fyQTC0QC5CMCr8I+MsNdnssOPBr6T09PktozJRAC8r88UxE3odJaoDC8lIQBeyD8y8oT795lCIJQSVD4FkL/"
      @"73Vkv5GfjZ4oiTAmmps6aXsqwVFoAvAqt697ljj7GAGMgxN2q7xJUMgUIpu9+GUzfZRjTrEKnc76KdYHKCQDn+"
      @"0wpqWhdoFIpgNfVx8bPlBF8JkdGnngOqkJURgC8gR1s/"
      @"EyZ2SkOViY1rYQAeJV+gCdc7GMqwBgI8SB4ZktP6QVgu9LPMFXCdSuxQ1BqAQhewEXT62CYlCyWXQRKKwBs/"
      @"AwRSi0CpRQANn6GGKUVgdIJABs/Q5RSikCpBICNnyFO6USgNALAxs9YQqlEoBStwN4QDylvml4HwxSG45wT//"
      @"yn8THkxgXA65oS4oHpdTCMAY6KRmPN5AKMCkBwsOc77vBjLGULhDgqnj5tmVqAsRpAz6k+Nn7GVsbAdR+"
      @"YPEBkJAIIzvPzFB+Gge2jxIdNzBMwEwH4wzzY+BkGtk8RfmniRxcuAN4WCE/"
      @"yYZh+5kxsDxaaAsgjR86B4xhROoapBAVvDxYmAFzxZ5hYbEGnc7io0WKFpABB0Y8r/gwzmLFgtFghtlIr4ocEN/"
      @"Zw0a9o9u/338bH/Tdk3z7/YypevgR49QrgxQv//zc3/Y8xxeEXBdFmLuX+o/"
      @"L+AdzmWwBo0FNTAG+9BXDoEMDk5I7hZ0UoBPh+YwPg+XP/v5k8uSQajVxtJ1cB4Lw/Jw4cAHj3Xd/"
      @"Y0fCzNPSkNJu+EKyvc7SQPbnXA/IVgKmpH3i/PwPQm6NXn5kBOH5cH8KbBgVhbQ3g22/"
      @"9KIEZlpZoNA7n9c1zEwA+3jskodGjwaPhl9noVWBE8PAhi8HwLIlGIxdbykUAvNC/Vvshj+9NHgzpq+Dpk4KRwaNH/"
      @"huTHCEO53FoKB8B4NA/ObOzACdP+gKQNWFlH71w+N9R9O4QHDiQT23hxQtfDO7c4aggGbmkApkLAIf+CUBjQ6M/"
      @"dWp4b4+GjcaFYfezZwD//vdOUW6YwlyYiuD7gwf9/z50KBtxwGiAhSAJmacCmQoAh/"
      @"4xycLw0ajRk+LbxkbxW3Lh1uORI/57FIa0sBDEp9P5bZa7AtkKAIf+g8Hc/pNP0hl+aOyh4ZcJjAjC+gW+T/"
      @"P7sRDEYU00Gkez+maZCQAf9BkAGsX8fPIcH8P6sHhWJcOYnd0pZibl9m2AlRXuKVCTWYNQJgLAd/"
      @"ZrQE+IHj+JIeCDv77uG33ZPH1SwsjgwoVkdQMUPhQC3jWIYitIBYYeIJKNAExN3QUhKnEbaqFgno8PftxwGA0fPd/"
      @"9+zS9HwoBviYYHcSF0wIVN0WjMfRZgaEFgAt/"
      @"EaDBX78eP9ynbvj9YCSAwhg3KuJoIJoMegOGF4Dp6QcAwBN+QtDo0fjjeH1Dht+REn7+5S+9NTq//"
      @"vX2FmLt1auCjocGJBUCjgb6GbogOJQAcOGvD8z1T52K97X4IBdo+P8rpVeUc2dm4P8dPQpOhED9/"
      @"OwZuM+eATx+DLWNjeLEAEVzYSFejQCjgYsXWQR2GOpugeEEgLf9fPDBxQc4TsjfbAJcu1bYA9zBtz/9CX7x4YeRRq/"
      @"8d8+fQ/fGDXjj229zXd8uMBKIWyy8ccOPnpihooCRtP8w8P7n0v57MkxOAvz1r4MbYdDT//"
      @"nPAMvLhXn9zvg4uNevwxt//COIN95I9G9RLGp/+AP8f0wV/vGP9A9KEjY3/ZOEYfehjt//3n+/"
      @"sVHEysrMxOL4eHvpxYvv0/zj1BEAe/8ETT3o9a9cKTTP/"
      @"5+33oLRW7egduDA0N8L0wJ58SKMqM4Q5EHcaAAFAyMqG4qnKqRsi2bzt2n+aSoB4Nw/"
      @"2OL79FP91+BDGeb6BdIdHwf5xReZGH+Iu7kJ3Q8+gFFR4CDpuKkV1wVQBM6JZjPxNOF0AmC795+"
      @"f972TDkMP5WspofbwIYgcTvL99+9/h1989lnx10nha42vuQ7bRSBlFJB4KrDn/dn49V+DYenp00Yexu6xY7kYP/"
      @"LGBx+Ae+RILt9by+3bfgoVDiqNAn/nL77wjzHbiBATcmoqcTNe8rHgQhR+e0lpiGP8GPIXnO+H/Ize/8MPc/"
      @"0ZzoULIHP9CQpQVPF3YxHQkfiocCIBsNr7xzH+5WXfWxli5L33Ms37oxBTU/Dzvn25/"
      @"gwlaPwoArqjzzaLAEYB09MJ+qyTRgCOY2e//yDjR2+P+WfBxb5e0CuLmZlCflYtzQm/"
      @"rAhzfV1bsM0iAJAoQo8tAIGyJFIXEoQHelSExm/41J6UEkRRD/"
      @"zkpJk0IARf86WlwSIQtyWbFrNJooD4EYCU9jX9TE7qt/pC4y/BBRleBDDMVJ4EFCY0gxgkAvh6oAjYx0dxvzCWAHgn/"
      @"mw77ose5C9/UX++RMYPgQAUhRgfNxsB9DJIBKam/GYtu5iLe7dgvAjAcew67Ydh461b+i60Ehl/0UhdJd4Eg0Tg1Ck/"
      @"lbOJWu3jOF8WTwCEiB1SkGB+Xm/8+MCVzPidIg3z5cvim4EGsbys/"
      @"5tcuDDc4NLqEctmBwqAnJqas2rrL5zWq+LOnVIOphBC+OPAC0A2m+"
      @"UTAEzJLl9W9wlgVIcpnT1FwbE4xcA4EYA94T96fV3Rb2XF6D6/DjRIt6CdCFnWE3hhn4CqCQv/"
      @"voNaimkxcEtQKwDWFf8w71eB4eWNG0WuJjHi8WOQOXcgdp49A6dk6c8uUASuXVN/"
      @"HqO7JDMJq019UDFQHwE4jjWvlDbvx4fqypWiV5QY5+VLcHNuRhIrKyn6xwtmbU0/"
      @"LOTqVVuahMagVtNu3w8SADu8fzibTsXycmVOmaGBdnMqBv73m29AlLD+EQlGa6qUaP9+gEtDD9StCid0n1QKgBf+"
      @"29L5pwv979zxPUpF8KKAy5ehm3Uq8Pw5jP7tb+X3/r0sLanrAZgG5HERa/mY1aUB6rmPtZodxb/jx/"
      @"Whf0mLfjpGNzdBDjo+m5DOf/"
      @"7jTQ2uFPj7o4CrGoEWFvxj29SnCfk9AZEnBXWDX7WhAwkGhf4XLxa5mkwRGP5mWPGuVXUA5/37O/cV9oN//"
      @"5MnfZGgjfKUWOR2rjWXfaAHUJ1swwe+5FV/Lfhwf/NNdt/vxInK1EH2gK/FvXvRPQDo/"
      @"c+cqe7vFpdO51dRV4lFp3Q2VP/xoVAZf0VDf0ZBmApEgaJgQ2+AYjdAJQD0q/"
      @"+60B+Nn3peaBuYCqj6F9AR0C8IRqb0ewQgqBjSjgAGef+qbHUxyVheVn+OfhQQ2RS0twg4MkLb+GGA919aKnIl+"
      @"fHqle/xsup9pxARNZv+W5S3x4/hW9WvY1czBrVaHQB27WlH7QLQ3v7TeX8K9/GHoMGePm16FeXjzh11uI/PBZW/"
      @"fxRSzvULwN4agBBvF7mmwtF5f4rbQeFuQJzWVzQM/Nr+N0pTdcIoIAoUANqnBffUAXYJQND9Vy90SUWi8/"
      @"5ra3S3guLcE3DypD9IE7+2/"
      @"+3QoSJWWRw6oac8OESIif46wO4IYGSErvED6Cu9VW10yYL5ef0x6JwuGjGGLgo4dYp2FNA33as/BaBdAFSF/"
      @"y9e0M79VOCDvrAw+L4Diuj6AkzcflQUQuxy8k7fJ4sZLG8C9P4qT2Zj0084Oz/OjH8KOwD9oOCrfi/"
      @"dRKiq02fj2wIQ5AZ0UwDe998Bjf/Wrfgz8so8AGQYVLMT0FnQTQN29QPsRAD+HiFdVPm/baE/"
      @"vg737iXL66kKgK7uQ7kY2GPrvSkAXQHQhf82ef+w0p/"
      @"Uu1EtkGIKoHIAtFuDIwRASrr5vy78tyUCGFTpV4ECSXV7FDQOgHIa0NPr4/"
      @"R8kO7ob5WaV2jST2rChzjNhZ66U3RUWF9XFwOPHSt6NcXgutu7ffRTgMlJu8P/"
      @"tJdhhOExZe8Pwe+"
      @"pqnFQnR7c0xDkCUDSO8UrhWpPF70b1eJWL0k9PxrE8rLvGW1BFQmieFJNA0ZHvYjfjwCkjHWRYCVRqbgNuT9GPkmKWe"
      @"Hd+zmPFi8djx9HfxyNn+p1Yt2uF/H7AtDXHUQKm/P/JD38+HqcPm1HVNQPRj2qAapUuwIDmw8jAJonAHXe71//"
      @"KnIlZoj78GLIf+UKzY6/uKgcAtXtQMd5E7bnAVDdATh4MPrj6OWoF7cgRgEQvd7Skh3p0CBUkQ/"
      @"VFEDKnggAgKYAqNTbBuOHAT38+MBjvs/"
      @"G76O7RYjmNWJ+ETDYDqBZBFT94Wx56FUXeays+Pm+LUIYB4yGVIJJsw4whrZfI+v9QRO+2ZD/Q0QEEG7x2dD/"
      @"kAaMilQXiFBkdHTCgVqNpvfX5W62VLp7f0/0cGfOsPHrUD0XNFMAACl/44Dr0owAVA0c6AVtqXavr+9sb12+zCH/"
      @"IGwrBLrurxxwHJoCoNsBsAUUOjR80NQDdGA4TNX7RaF6jaimAI4z4ZDtAtRFADaR5vfF1y4cCHr1ah6rKifPnkV/"
      @"HF8Pii3BUo451u0A2BQBpCEcFRYWw2yKAnTXqVMUAMd50wEhfmN6HbmgCttsiwCSoBoV9u67plZUPKrng2IaIOVE9OW"
      @"glEmTC9uAblQYtXsBdFhWB3BQBUwvIhdUYasuzLOVQaPC9u0rekXmsGmnRMqJqLsBGZv45JPBY7Ap5r+"
      @"MB10BIBqyZQYa9fXr8U672VQ3UUWIRJ+nGtmTgCo4Bdgp9sV9qPk1o4kQFhYBbWdyMpnxA2+dUoZuCsDs5fhxP+"
      @"dPmtNvbOS1IsYwLAC2MD+fbjQ49XsBLIduCmBTQ0cc+"
      @"F6AeFjWQEZXALjhxyftTbe23AsQF6LPk30pgG0RQJrLLdDr2/"
      @"Y6hVjW80A3AmDPpb8UNQr0+hcvAty+"
      @"neeqyo1KAIhuhTogZdv0InLBsoaOSGYS3Pe6uelPDLJlXqIKm2oAUrbppgCqP5gtR1shwSSblRWAGzfyXk350YX/"
      @"RCMAugKgSgFsOtgySABQJDHft+0qMBW614tiBBC0ArdJTgZWVW1tOto6yKNdvsxdfr2oXi+"
      @"qr5EQbbpFQNUfzaYagCpstfkeQB2qOZJEvT94EYCUP4IQpteRPbqcDUM9Wx/"
      @"+5WUO+VWoUgCqz0oQAWyZXkcu6G58pTrmuZ/eIZe2Xv2dBFWBmOqWsuv+5IAQNAUANFNebRGA9fWd/8Z83/YtPh2Y/"
      @"9t2k5QQWw64Ls0+ANCkAbYIwKNHfsgPKVtZx8ft6YzTPRNUhdN127QjANUxVvxj2/"
      @"Jgq+69H8S+fX4n4cmTWa+onKguAKWa/"
      @"4M3FrztQLdLNwLQXflsSxSQhvn5nTMEp07ZIZaq0WhUvT+EKQAAXQHQFQJpXvk8HGjoCwsAFy7s/"
      @"liSluKqYqMAvH7ddkSrtUV2JwA0IXCcYZg2Ed4IFDU3gHq0pHsWqBYAAbbQ9sNGILpRgKoOgH90G0LbOKhuBAqh/"
      @"jqphqVg/"
      @"k91CzCweV8ApPze9GpyQxfCHTtW5ErKie5GoBDq3ZM2hv8AP0LPPAC6KUA42SaKNMMyKDHoRiAb0M1M6O2joEcLeiKA"
      @"lunV5IquDmDrwz8/D/Dpp/G+luhRWA9V+I+/M+0I4DvYFgDXpS0Ajx+rP2dbGhBV6R+EqqOSAnaG/"
      @"8hP0JMC0C0CAqcB2+gq/Tqo3guAf3tV+P/oUdGrKRTRaHhhsScA3lYg1dFgIbo0wIYtwYMH9ZV+FSicVLvhVNEf/fB/"
      @"O+LvnQdAuuLhpQGqc91pZuZXDQz701Tzr13LYzXmwddCFf09fFj0aormx/A/"
      @"dgRACNp1ADR+VVg3M0O3GBhGN2l+"
      @"P4yaqO6D62ogupoRDbbD4d4IgLYAgGZbB42D6qGXNBeDYMiPITDRyzA8769qb6YsejtEpACdDn0BwIdaldtRPPSCD3r"
      @"SnH9lxR8XRn3rT/W3xt+fOj22vi0AwZkA+iKguuuOYhSQ5BAPpkjLy/THg6Movvde9OfoF/"
      @"+QVmDrHruHgkpJuxAIA6ra1KKAuFuc+OCfOWPHuDD0/"
      @"qpiqA03IvXZeL8A0I8AENWDTi0KiHMJSjghmH7e6xu+qviHIkh8799DiCe9/7tbAFx3tej1GAH/"
      @"0KocFx8QKrcHDdr2w5D/yhXSY693oav82+D9wcv/dx382yUAVjQEhSwtqT939WqRK8kPlWHbOCEYxVDX92+D9/fz/"
      @"132HXUxyNfFrccguh0BKt2BUdt4+Duj8dMvdu3m1i3152zx/hEp/"
      @"l4BEMKONAA0OwIQdM5VvSDYn9evrPjGb0O+38v8vDodQiG0w/"
      @"tH2vaeK4FkvT4GtdoPADBW2MJMcv26ulqOD0eV98N7z7on3eIKIyAKkYKu0/"
      @"PECXsEsdP5Ve8WIEQJACKnp58AgB3H5NBA7t2rvrdnkmPXtehrotE42v9B1eWgdtQBIPCMulSAoQn+3W3J/cHL/"
      @"+9GfThaADqdyC8my/376S/QYKoJ/r1t2f5Eut3IJr9IAQjyBLss4tAh0ytgisSmQTAY/vdt/"
      @"4WoUgAgPx+gF117KEMT3YlAeihTerUAdDo381pN6bBhIAizlzRHpatIp6Pc2lcKgDVpAJWmHyY5dvztleE/"
      @"DEgBwIrdAPb+djM/b3oF+aKo/ofoBcDfDaB7aYiuP5yxA+pRgKL6H6IVAPJDQpLMxmfoQtUJSHlXF/"
      @"5DjBQA0RybqzDs/ZkQ3YiwKhPjXM9AAQguEKCXBrD3Z3qhNAgGPO/"
      @"fFo3GwBpenAgA+Xz4FZUIVHvKeR+THGrj4ISIZbPxBIBaT8DMDDf+MLuhNg5Os/ffSywBCCYF0ZkTwOE/"
      @"EwWVKCBG8S8kbgoQO6QoPdz2y6hA46fQHizEV3G/NLYABMXA6ncGsvdndFR/"
      @"Z2gtvPk3DvEjAJ9qbwn2TshhmCiq3hg0oPOvn0QC4ClLlacGU2/7ZLKhqs+JlG3RbMYO/yFFBIA/"
      @"pJpRAHr+Kis7UxzVjQIWk/"
      @"6DxAIgNjbuVjIK4NyfSULVooAU3h9SRQBQwSiA236ZpGAEUK0bohJ7f0grAJWLAtj7M2moSmNQSu8PqSMAqFAUsH8/"
      @"e38mHdU5JJTK+yO1tP8QowA5PX22EvcHbG5W5Q/JlImXL8s/OXgI7w/"
      @"DCEDAUukFAP+Ap0+bXgXD5EVq7w+qm4GSYNUtQgxTLlZFo/"
      @"H+MN8gfQ0gRIhLQ38PhmGS0+kMbXtDC4B4+"
      @"rQFUtI4KMQwVSHBiT8dw0cA4A0eXCQ5NYhhyoiUbeh2M9mFy0QAvHkBrluNbUGGqT6LWXh/yKII2AsXBBkmZ/"
      @"xtv99m9e2ySQFCOp3zmX4/hmF20+3uueN/GDIVgCAs4VSAYfJhKavQPyTTFCBETk9/BwD1PL43w1hJxqF/"
      @"SLYpQIgQnAowTJZkHPqH5CIAXm8ApwIMkxWZh/4huaQAIZwKMMyQ5BT6h+STAoR0Ou9zgxDDpETKrbxC/"
      @"5BcBcALW7hBiGHSIURuoX9IvhGAPzfgJp8VYJiESPm5aDRyv5IvdwHw6HYXKzVCjGFM4vf6D3XOPy6FCIB3VsDPZbge"
      @"wDA6grzfs5kCKCYC2KkH8OwAhtHzcd55fy+"
      @"FCQCE04S5P4BhVCwNM98vDbn2AaiQ09MPAGDOxM9mmFIi5apoNoca75WGQiOAbTqd81wUZJgAv+"
      @"hnpH3eiABsFwVZBBjb8Y2/"
      @"sKJfP0ZSgBD5zjt1kPIJAIyZXAfDGMGv+"
      @"B8usujXj5kUICA4NFR43sMwJeG8SeMH0wKAiEZjDVyXjw8zdiHEedFsrppehnEBAN4eZOxjSTx9etf0IqAsAgB+"
      @"JLDIIsBYwFLwrJeC0ggAsAgw9CmV8UPZBABYBBi6lM74oYwCACwCDD1KafxQVgEAFgGGDqU1fiizAACLAFN9Sm38YLo"
      @"TMC7yyJGPwXE+M70OhomNEOfLstWnoxICgMipqTkQ4ktuG2ZKjZRbIMT7XoNbBaiMACCyXp+"
      @"AkZEnIMSE6bUwzB78gz3vi1arZXopcamUAACLAFNWdk71VeqEa6mLgFF4L3C3exgAjPdRM4yHlKumT/"
      @"WlpXIRQC9yenoRABZMr4OxmtJX+nVUWgDA3yE4F+wQcHGQKQ4pt8BxLlWh0q+j8gIAXBdgiqai+X4UlasBRLFdF+"
      @"AbiJi8wWesovl+FCQigF6CpqEFTgmYTPH395eKuK6rSMgJAHBKwGRPCzqd96l4/"
      @"V5ICkAI7xIwGVDpKv8gSAsAcDTApAe9/"
      @"vkqdfWlgbwAhHA0wCSAtNfvxRoBAI4GmMGsBV6fXK6vwioBCPGah4RYYCFgPIhW+ONgpQDATjSwCEKcNb0WxiD+"
      @"vv6iqau5TGOtAIQEQvAZCMG3FdsFhvuXqBf5BmG9AIRwWmANa0GRrxIDO/"
      @"KGBaAPFgKi+"
      @"DdRL4pm8yvTSykTLAAKWAiIwIavhQVgACwEFYUNPxYsADEJ5g6cBYBZ02thtHCOnwAWgITI6elZkPIcbx+WjlUA+"
      @"JwNPxksACnxtg9rtTmQ8iNODwzhN/"
      @"B8Dp3OTVv38YeFBSADvDsLAOY4KigA3+"
      @"hbHOZnAwtAhnhRgePMcq0gF9aC6btfsbfPDhaAnAg6DE8EHYYsBulgo88ZFoAC4MggJmF4z0ZfGCwABSPr9TEYGZn1h"
      @"ECIGQCom16TUfz9+"
      @"q9BiFXodFps9MXCAmCYIFWoWyQI6OHXQcoWuO4qG7xZWABKhhch1Gp1kPJtEAIjhYnKigJ6d8dZA9dtgRDfs4cvHywA"
      @"FSFoQBoDIVAM3vaEQcoJEMLs+HM/b297ubvr/uR59pGRFrx+3WZjLz8sABXHixhGRyc8cXDdCXAc/"
      @"78d501PILwvkjuNSoOalvycPPza9vZ7NG4htsB12957x2mzkVef/wsAAP//3g3hBw9bHUoAAAAASUVORK5CYII=' "
      @"/> Making a note here, huge success!";
  got = [SNTBlockMessage stringFromHTML:html];
  XCTAssertEqualObjects(got, @"This was a a triumph  Making a note here, huge success!");
}

@end
