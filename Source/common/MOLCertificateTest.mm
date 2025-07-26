/// Copyright 2015 Google Inc. All rights reserved.
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

#import <XCTest/XCTest.h>

#import "Source/common/MOLCertificate.h"

@interface MOLCertificateTest : XCTestCase
@property NSString *testDataPEM1;
@property NSString *testDataPEM2;
@property NSData *testDataDER1;
@property NSData *testDataDER2;
@property NSString *testDataPrivateKey;
@property NSString *testNTPrincipalName;
@end

@implementation MOLCertificateTest

- (void)setUp {
  [super setUp];

  NSString *file = [[NSBundle bundleForClass:[self class]] pathForResource:@"GIAG2" ofType:@"pem"];
  self.testDataPEM1 = [NSString stringWithContentsOfFile:file
                                                encoding:NSUTF8StringEncoding
                                                   error:nil];

  file = [[NSBundle bundleForClass:[self class]] pathForResource:@"apple" ofType:@"pem"];
  self.testDataPEM2 = [NSString stringWithContentsOfFile:file
                                                encoding:NSUTF8StringEncoding
                                                   error:nil];

  file = [[NSBundle bundleForClass:[self class]] pathForResource:@"NTPrincipalName" ofType:@"pem"];
  self.testNTPrincipalName = [NSString stringWithContentsOfFile:file
                                                       encoding:NSUTF8StringEncoding
                                                          error:nil];

  file = [[NSBundle bundleForClass:[self class]] pathForResource:@"GIAG2" ofType:@"crt"];
  self.testDataDER1 = [NSData dataWithContentsOfFile:file];

  file = [[NSBundle bundleForClass:[self class]] pathForResource:@"tubitak" ofType:@"crt"];
  self.testDataDER2 = [NSData dataWithContentsOfFile:file];

  self.testDataPrivateKey = @"-----BEGIN RSA PRIVATE KEY-----"
                            @"MIICXQIBAAKBgQDk2F9JsQQjKSveMwazXzFLbiiOD0RkDiRX1LTmQtVdi514F6l/"
                            @"RwohMrwxQpsoKwyzEngX58+PrGZ0XZrcVcHn666521IxswHZPaacBlWZ7k9XkB2Y"
                            @"m8mxULMBG9iIv/k5tRJN3MuJdtbQc8qLBsyFFsytL8hSRvBQNyP7N/OqnQIDAQAB"
                            @"AoGATpLUNNMonoH2Y/aVKGVY4ZNTLWOkkc4hQF7yNdVguRvE14UYV3Em0zs+TpOV"
                            @"/na5h4qh3WNkaupAy1eQYnK3fqmGLZw5e8cBCgUkIi8P//zMrKlgJKwfzQHSdJSP"
                            @"pkCvj2kliFwNzbA026jcwGEYV+uRCNazO5ldtOcP5EDb+qkCQQD/Ihc2mjtf7oq1"
                            @"VZSzo0xch3NtzTZMyFCRWqMpXHQO1fZTAe96EbI85zsTRmOVuqKnGxBvvtHJr2QY"
                            @"UoZ72+f7AkEA5Z9qte46t1F1ME3ZzWd6Ob1obCmuAa75eTPAgQKc+1bSVeFMGLTz"
                            @"n2M9wZ+mIpWvJp8QRdmOi0zpEArHqa68RwJBAO1YoY/CW4obOB8JxpR3TgqmV9PG"
                            @"HMXBdHJEh5Vq1O0YT1dZbZd57v6JfoOn7+zS+43Jt7i9JB0kdVHLNCD1qxECQQC3"
                            @"wXGGEhVO6pMbitGHvQ1k85yDIn+rvTjLs4yUMWErCfnc3CUniHeFz8d2EarD9oFq"
                            @"KNS+8TFPbMb+HYJW2gy1AkAHGBUKmZNPGiKJEUjc5jN1uN+B9OMLDX+3rMUO9Q2x"
                            @"jsn0m7Mobx+pPqbIAvsklMtA4Qdrt5a9pnwEgTWoJPYA"
                            @"-----END RSA PRIVATE KEY-----";
}

- (void)tearDown {
  [super tearDown];
}

- (void)testInitWithDER {
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataDER:self.testDataDER1];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.commonName, @"Google Internet Authority G2");
  XCTAssertEqualObjects(sut.orgUnit, nil);
  XCTAssertEqualObjects(sut.orgName, @"Google Inc");
  XCTAssertEqualObjects(sut.countryName, @"US");
  XCTAssertEqualObjects(sut.issuerCommonName, @"GeoTrust Global CA");
  XCTAssertEqualObjects(sut.issuerOrgName, @"GeoTrust Inc.");
  XCTAssertEqualObjects(sut.issuerOrgUnit, nil);
  XCTAssertEqualObjects(sut.issuerCountryName, @"US");
  XCTAssertEqualObjects(sut.SHA1, @"d83c1a7f4d0446bb2081b81a1670f8183451ca24");
  XCTAssertEqualObjects(sut.SHA256,
                        @"a047a37fa2d2e118a4f5095fe074d6cfe0e352425a7632bf8659c03919a6c81d");
  XCTAssertEqualObjects(sut.validFrom, [NSDate dateWithTimeIntervalSince1970:1365174955]);
  XCTAssertEqualObjects(sut.validUntil, [NSDate dateWithTimeIntervalSince1970:1428160555]);

  sut = [[MOLCertificate alloc] initWithCertificateDataDER:self.testDataDER2];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.commonName,
                        @"TÜBİTAK UEKAE Kök Sertifika Hizmet Sağlayıcısı - Sürüm 3");
  XCTAssertEqualObjects(sut.orgUnit,
                        @"Ulusal Elektronik ve Kriptoloji Araştırma Enstitüsü - UEKAE");
  XCTAssertEqualObjects(sut.orgUnits[1], @"Kamu Sertifikasyon Merkezi");
  XCTAssertEqualObjects(sut.orgName, @"Türkiye Bilimsel ve Teknolojik Araştırma Kurumu - TÜBİTAK");
  XCTAssertEqualObjects(sut.countryName, @"TR");
}

- (void)testInitWithValidPEM {
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testDataPEM1];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.commonName, @"Google Internet Authority G2");
  XCTAssertEqualObjects(sut.orgUnit, nil);
  XCTAssertEqualObjects(sut.orgName, @"Google Inc");
  XCTAssertEqualObjects(sut.issuerCommonName, @"GeoTrust Global CA");
  XCTAssertEqualObjects(sut.SHA1, @"d83c1a7f4d0446bb2081b81a1670f8183451ca24");
  XCTAssertEqualObjects(sut.SHA256,
                        @"a047a37fa2d2e118a4f5095fe074d6cfe0e352425a7632bf8659c03919a6c81d");
  NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
  dateFormat.dateFormat = @"yyyy-MM-dd HH:mm:ss Z";
  XCTAssertEqualObjects(sut.validFrom, [dateFormat dateFromString:@"2013-04-05 15:15:55 +0000"]);
  XCTAssertEqualObjects(sut.validUntil, [dateFormat dateFromString:@"2015-04-04 15:15:55 +0000"]);
  XCTAssertTrue(sut.isCA);
  XCTAssertEqualObjects(sut.serialNumber, @"146025");
  XCTAssertEqualObjects(sut.dnsName, nil);

  sut = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testDataPEM2];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.commonName, @"www.apple.com");
  XCTAssertEqualObjects(sut.orgUnit, @"ISG for Akamai");
  XCTAssertEqualObjects(sut.orgName, @"Apple Inc.");
  XCTAssertEqualObjects(sut.issuerCommonName, @"VeriSign Class 3 Extended Validation SSL SGC CA");
  XCTAssertEqualObjects(sut.issuerOrgName, @"VeriSign, Inc.");
  XCTAssertEqualObjects(sut.issuerOrgUnit, @"VeriSign Trust Network");
  XCTAssertEqualObjects(sut.issuerOrgUnits[1],
                        @"Terms of use at https://www.verisign.com/rpa (c)06");
  XCTAssertEqualObjects(sut.SHA1, @"96df534f6f4306ca474d9078fc346b20f856f0d4");
  XCTAssertEqualObjects(sut.SHA256,
                        @"129d39ff4384197dc2bcbe1a83a69b3405b7df33254b1b1ee29a23847a23555a");
  XCTAssertEqualObjects(sut.validFrom, [dateFormat dateFromString:@"2013-11-14 00:00:00 +0000"]);
  XCTAssertEqualObjects(sut.validUntil, [dateFormat dateFromString:@"2015-11-14 23:59:59 +0000"]);
  XCTAssertFalse(sut.isCA);
  XCTAssertEqualObjects(sut.serialNumber, @"5E FA 67 0E 99 E4 AB 88 E0 F2 0B 33 86 7B 78 4D");
  XCTAssertEqualObjects(sut.dnsName, @"www.apple.com");

  sut = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testNTPrincipalName];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.ntPrincipalName, @"lha@TEST.H5L.SE");
}

- (void)testInitWithValidPEMAfterKey {
  NSString *pemWithKey = [self.testDataPrivateKey stringByAppendingString:self.testDataPEM1];
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:pemWithKey];

  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.commonName, @"Google Internet Authority G2");
}

- (void)testInitWithEmptyPEM {
  NSString *badPEM = @"-----BEGIN CERTIFICATE----------END CERTIFICATE-----";
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:badPEM];
  XCTAssertNil(sut);
}

- (void)testInitWithTruncatedPEM {
  NSString *badPEM = @"-----BEGIN CERTIFICATE-----"
                     @"MIICXQIBAAKBgQDk2F9JsQQjKSveMwazXzFLbiiOD0RkDiRX1LTmQtVdi514F6l/";
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:badPEM];
  XCTAssertNil(sut);
}

- (void)testInitWithInvalidPEM {
  NSString *badPEM = @"This is not a valid PEM";
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:badPEM];
  XCTAssertNil(sut);

  badPEM = @"-----BEGIN CERTIFICATE-----Hello Thar-----END CERTIFICATE-----";
  sut = [[MOLCertificate alloc] initWithCertificateDataPEM:badPEM];
  XCTAssertNil(sut);
}

- (void)testInitWithMultipleCertsInPEM {
  NSString *multiPEM = [self.testDataPEM1 stringByAppendingString:self.testDataPEM2];

  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:multiPEM];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.commonName, @"Google Internet Authority G2");
}

- (void)testArrayOfCerts {
  NSString *multiPEM = [self.testDataPEM1 stringByAppendingString:self.testDataPEM2];

  NSArray *certs = [MOLCertificate certificatesFromPEM:multiPEM];

  XCTAssertNotNil(certs);
  XCTAssertEqual(certs.count, 2);
  XCTAssertEqualObjects([certs[0] commonName], @"Google Internet Authority G2");
  XCTAssertEqualObjects([certs[1] commonName], @"www.apple.com");
}

- (void)testPlainInit {
  XCTAssertThrows([[MOLCertificate alloc] init]);
}

- (void)testEquals {
  MOLCertificate *sut1 = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testDataPEM1];
  MOLCertificate *sut2 = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testDataPEM1];

  XCTAssertEqualObjects(sut1, sut2);
}

- (void)testDescription {
  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testDataPEM1];

  XCTAssertEqualObjects([sut description],
                        @"/O=Google Inc/OU=(null)/CN=Google Internet Authority G2/"
                        @"SHA-1=d83c1a7f4d0446bb2081b81a1670f8183451ca24");
}

- (void)testSecureCoding {
  XCTAssertTrue([MOLCertificate supportsSecureCoding]);

  MOLCertificate *sut = [[MOLCertificate alloc] initWithCertificateDataPEM:self.testDataPEM1];

  NSMutableData *encodedObject = [[NSMutableData alloc] init];
  NSKeyedArchiver *archive = [[NSKeyedArchiver alloc] initForWritingWithMutableData:encodedObject];
  [archive encodeObject:sut forKey:@"exampleCert"];
  [archive finishEncoding];
  NSKeyedUnarchiver *unarchive = [[NSKeyedUnarchiver alloc] initForReadingWithData:encodedObject];
  MOLCertificate *newCert = [unarchive decodeObjectForKey:@"exampleCert"];

  XCTAssertNotNil(newCert);
  XCTAssertEqualObjects(newCert, sut);
  XCTAssertEqualObjects(newCert.SHA1, sut.SHA1);
}

@end
