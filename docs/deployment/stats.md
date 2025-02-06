---
title: Stats
parent: Deployment
nav_order: 6
---

# Stats

Santa clients v2025.2 and up can optionally send a small amount of stats data to
a statistics service run by North Pole Security, to help guide decisions during
the development process.

{: .important }
Statistics collection is **opt-in**. The `EnableStatsCollection` or
`StatsOrganizationID` keys are required to enable stats collection; if neither
are set, collection is **disabled**.

### What's collected?

The set of details collected will always be publicly available in the
`SubmitStatsRequest` message in the
[stats proto](https://github.com/northpolesec/protos/blob/main/stats/v1.proto#L17)
file.

* `machine_id_hash`: A SHA-256 of the machine's hardware UUID.

* `santa_version`: The full Santa client version number (e.g. 2025.1.80).

* `macos_version`: The macOS version number (e.g. 15.2).

* `macos_build`: The macOS build ID (e.g. 24C101).

* `mac_model`: The Mac hardware model identifier (e.g. Mac15,7).

* `org_id`: The value of the optional `StatsOrganizationID` config key
  (see ["What is an organization ID?"](#what-is-an-organization-id)).

Any changes to the collected data will be clearly called out in the release
notes for future client versions.

### Where is the data sent?

Stats are submitted to `polaris.northpole.security`, which is running a gRPC
service receiving SubmitStats requests. The data is immediately submitted to a
BigQuery table. The source code for Polaris is at
https://github.com/northpolesec/polaris

### Why are you collecting this data?

North Pole Security is a small company and we want to focus our resources on
making the most meaningful changes we can. This data will help us do that.

Examples:

* Knowing what versions of macOS are being used by Santa users will help
  ensure that our deprecation policies align with the needs of the community

* Knowing what Mac hardware is most commonly running Santa will help us
  know whether to write features taking advantage of newer hardware. E.g.
  is it OK to restrict features to Apple Silicon, or make use of TouchID?

* Knowing how often versions of Santa are being upgraded will help us know
  how long a feature needs to be marked as deprecated before it can
  reasonably be removed.

### What about privacy?

The information submitted in the SubmitStats request cannot be used to
identify a user or organization.

{: .warning }
The exception to this is the `org_id` field, which is only populated if
explicitly configured. See the
["What is an organization ID?"](#what-is-an-organization-id) section below.

The only data that is unique to a machine is the `machine_id_hash` which is used
only to have some identifier that can uniquely count "machines". This field is
a SHA-256 hash of the Hardware UUID of the machine so while it does uniquely
identify a machine, we cannot use it to identify anything else about that
machine.

While, as a gRPC server, Polaris could see the IP address of submitting clients,
we explicitly do not record this information or log individual requests.
However, we understand that even though the Polaris code is open and you can see
that we are not recording the IP address, this is not a strong guarantee. We are
investigating using anonymization mechanisms such as
[Oblivious HTTP](https://datatracker.ietf.org/doc/rfc9458) but that is not
currently implemented.

### How do I opt-in?

Set the `EnableStatsCollection` key to `true` in your Santa configuration
profile:

```xml
    <key>EnableStatsCollection</key>
    <true/>
```

### What is an organization ID?

For organizations that have a support contract with North Pole Security, we will
provide a unique identifier to populate in the Santa configuration profile and
this will be transmitted with each submission. This allows us to know how many
machines each supported company has using Santa and on which Santa versions.

You should not populate the `StatsOrganizationID` key unless given a unique ID
by North Pole Security, Inc.

