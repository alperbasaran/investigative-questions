# Falsifiable Investigative Questions for Digital Forensics

A practical question bank for students and practitioners of digital forensics and incident response. The examples focus on Windows hosts, disk and memory evidence, and network traffic. They are starting points to adapt to a case, not a mandatory checklist or a substitute for artifact validation.

**Ask a question the evidence could challenge. State what the evidence actually establishes.**

## Contents

- [How to use this guide](#how-to-use-this-guide)
- [1. Acquisition and integrity](#1-acquisition-and-integrity)
- [2. Evidence coverage and time](#2-evidence-coverage-and-time)
- [3. Delivery and execution](#3-delivery-and-execution)
- [4. Authentication and remote access](#4-authentication-and-remote-access)
- [5. Persistence](#5-persistence)
- [6. User activity and devices](#6-user-activity-and-devices)
- [7. File systems and recovery](#7-file-systems-and-recovery)
- [8. Memory](#8-memory)
- [9. Network](#9-network)
- [10. Manipulation and anti-forensics](#10-manipulation-and-anti-forensics)
- [11. Staging, exfiltration and impact](#11-staging-exfiltration-and-impact)
- [12. Reporting and challenge](#12-reporting-and-challenge)
- [Worked examples](#worked-examples)
- [Investigation worksheet](#investigation-worksheet)
- [Technical references](#technical-references)
- [Editorial notes on the original question bank](#editorial-notes-on-the-original-question-bank)

## How to use this guide

### A question is not yet a conclusion

An investigative question identifies an uncertainty. A hypothesis proposes an answer that can be tested. An observation is something recovered from the evidence. An inference connects observations to a claim.

For example:

- **Question:** Did `report.exe` execute on `WS-01` between 09:00 and 10:00 UTC?
- **Hypothesis:** A process instance of that file started in that interval.
- **Expected observation:** A process-creation record with a matching host, path, timestamp and, where available, file hash.
- **Supporting observation:** A retained Sysmon Event 1 records such a process instance.
- **Challenge:** The record instead identifies a different file hash. This challenges the identification of that process as the particular file under investigation; it does not exclude another run elsewhere in the interval.
- **Unresolved result:** No matching record is found, but process auditing was disabled. The question remains unresolved.

**Falsifiable does not mean that every question has an available yes/no answer.** A historical event can leave incomplete, missing or misleading traces. Positive evidence can support a claim without making it certain; failure to find an expected trace contradicts the claim only to the extent that the trace was reliably expected to exist and survive.

Open questions such as “Which files changed?” are useful discovery questions. Convert their results into bounded claims such as “File F was renamed between T1 and T2.” A narrative answer can be evidence-based and testable; a numeric answer can still be unjustified.

### Bound the claim

Replace the placeholders before investigating:

| Placeholder | Meaning |
|---|---|
| H / A / B | Identified host or endpoint; resolve address ownership at the relevant time. |
| U | Account identified by SID or another durable, appropriately scoped identifier. |
| P / Q | Process instance: host, PID, creation time and, if available, process GUID. |
| F / X | Specific file or object: path plus hash or another appropriate identity. |
| V / E / M | Identified volume, exhibit or memory acquisition. |
| D | Destination identified by address, service, account or object as appropriate. |
| W | Explicit interval, preferably `[T1, T2)` in UTC, with original time basis retained. |

Keep one main proposition per test. Split “U ran a tool, stole files and deleted backups” into separate execution, access, transfer and deletion questions. Do not make the question narrower than the incident requires: repeat it across relevant hosts, accounts, paths and intervals.

### Record three possible outcomes

| Outcome | Meaning | Example wording |
|---|---|---|
| Supported | Reliable observations support the bounded claim; assess competing explanations. | “A process-creation record identifies F starting on H at T.” |
| Contradicted | Reliable observations conflict with the claim or a necessary part of it. | “The recovered task action names C, whereas the claim specifically names B.” |
| Unresolved | Evidence is missing, ambiguous, insufficiently reliable or outside coverage. | “No matching record was found; retention does not cover W.” |

A claim can be supported by one sufficiently direct, validated source. Corroboration increases confidence when it is relevant and independent. Two parser exports of the same event are not two independent sources. Two sources with the same collection gap do not eliminate that gap.

For a negative finding, document: whether the source was enabled, whether it records this behavior, its filters and exclusions, retention, acquisition coverage, time uncertainty, parser behavior and the exact search performed. Prefer “not observed in the collected sources” over “did not happen” unless the evidence warrants the stronger statement.

In the tables below, **Evidence to examine** identifies possible sources, not guaranteed answers. **Challenges and limits** identifies contradictions, alternatives and gaps; an alternative explanation is not automatically a falsification.

## 1. Acquisition and integrity

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| A01 | Does the working copy of E match its recorded intake hash? | SHA-256 over the same byte representation; intake record. | A mismatch contradicts equality. Check scope and transfer errors before deciding the cause; a match does not establish original authenticity. |
| A02 | Does E pass its acquisition tool's integrity verification? | Verification output; stored acquisition digest; segment completeness. | A failed verification requires investigation. Successful verification can coexist with unreadable source sectors. |
| A03 | Were unreadable sectors recorded during acquisition of E? | Acquisition logs; bad-sector map; error-handling settings. | Identify affected ranges and substituted bytes. Absence of a bad-sector report is meaningful only if errors were recorded. |
| A04 | Does E contain the full addressable range specified in the acquisition scope? | Source geometry; logical sector size; acquired ranges; tool logs. | Compare uncompressed addressable data, not E01 container size. Selective collection may be complete for its scope but incomplete for the device. |
| A05 | Is E a whole-device image, a volume image or a logical file collection? | Acquisition manifest; parsed partition/volume structures; offsets. | These are different evidence scopes. Logical versus physical sector size does not identify the acquisition type; do not assume 512-byte sectors. |
| A06 | Has the preserved evidence file E changed since the baseline was recorded? | Current and baseline hashes for the same file or image data stream. | A mismatch shows changed bytes or a comparison problem, not who changed them. File timestamps alone are insufficient. |
| A07 | Was V encrypted at acquisition? | Encryption metadata; acquisition-time status; collection method; keys if available. | A readable image may be a decrypted acquisition of an encrypted volume. Possession of a recovery key does not establish encryption state. |
| A08 | Does the custody record account for each documented transfer of E? | Exhibit identifiers; handlers; dates; transfer records; hashes where applicable. | Missing documentation is a provenance gap. A consistent hash does not repair undocumented custody. |
| A09 | Did live collection alter artifacts relevant to the investigation? | Collector logs; command history; process/file events; collection start and end. | Live acquisition changes state. Identify attributable changes rather than claiming the collection was inert. |

## 2. Evidence coverage and time

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| C01 | Was the required audit source enabled on H throughout W? | Historical audit policy; sensor configuration; deployment and health records. | Current configuration does not prove past configuration. Enabling a source does not guarantee delivery or retention. |
| C02 | Do retained records in source S cover W without identified collection gaps? | Earliest/latest records; collector health; sequence continuity where meaningful; retention. | Endpoints alone do not prove continuous coverage; an interval without events may be inactivity or a gap. |
| C03 | Does timestamp field T represent the event time claimed in the timeline? | Source schema; raw record; storage time basis; parser conversion. | Event time, ingestion time, file time and UI-rendered local time are different. Preserve original values and conversion rules. |
| C04 | Are the clocks of H1 and H2 aligned closely enough to establish the proposed ordering? | Shared events; time-service records; measured skew and uncertainty. | UTC conversion does not correct skew. Overlapping uncertainty intervals may prevent ordering. |
| C05 | Does the address attributed to H belong to H at the time of event E? | DHCP leases; VPN/NAT mappings; endpoint inventory; source ports where required. | Present-day DNS and reused IP addresses can misidentify the historical host. |
| C06 | Do the records attributed to U refer to the same account identity? | SID; tenant/object ID; domain context; historical directory records. | Display names and UPNs can change; recreated accounts may reuse names. Account identity still does not identify the human operator. |

## 3. Delivery and execution

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| E01 | Was F delivered to H through the specified channel during W? | Mail attachment records; browser download database; proxy/service records; file hashes. | A download request need not complete. A file's presence alone does not identify its delivery route. |
| E02 | Did a process instance of F start on H during W? | Sysmon 1; Security 4688; EDR process records; appropriately interpreted Prefetch. | Amcache and modern ShimCache entries alone do not establish execution. Missing Prefetch does not exclude it. |
| E03 | Does the recovered file F match the delivered object X byte for byte? | Full-file SHA-256 over both objects. | A mismatch contradicts byte identity, not necessarily a delivery relationship: extraction, decoding or modification may explain it. |
| E04 | Does the observed filename differ from the PE resource's OriginalFilename value? | PE version resources; observed path; available inventory metadata. | A difference supports a naming discrepancy, not a historical rename or concealment intent. The resource value is editable. |
| E05 | Did F change from path/name X to Y during W? | USN rename records; EDR file events; stable file reference with sequence number. | Matching contents at two paths may represent copies. Prove the rename separately from a resource-name mismatch. |
| E06 | Did process P start with command-line argument A? | Raw Sysmon 1; 4688 with command-line auditing; EDR. | Missing/truncated command lines leave uncertainty. A recorded argument does not prove the requested operation succeeded. |
| E07 | Did P execute in the security context of U? | Process-creation security fields; token/session telemetry. | Separate creator identity, target process identity and later impersonation; “SYSTEM” does not identify a human. |
| E08 | Is Q recorded as the parent of process P? | Process GUIDs or PID/time correlation; endpoint telemetry. | Parent spoofing and PID reuse can mislead. A parent named explorer.exe does not prove a deliberate user launch. |
| E09 | Did P create or modify the specified object O during W? | File/registry auditing; relevant Sysmon events; EDR; object content. | Sysmon 11 concerns file creation/overwrite, not every file modification. A nearby timestamp is not process attribution. |
| E10 | Did P execute the specified script content during W? | PowerShell script-block logging; engine/operational logs; AMSI/EDR where retained. | A script file or encoded command alone establishes neither complete content nor successful execution. Distinguish logged processing from the success of individual actions. |

## 4. Authentication and remote access

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| L01 | Did H record a successful logon for U during W? | Security 4624; authentication-provider and identity-service records. | Interpret logon type, authentication package and source. Authentication is not proof of malicious activity or interactive use. |
| L02 | Was the logon session associated with the claimed source endpoint A? | Logon fields; VPN/NAT records; server and client telemetry. | Relays, proxies, missing fields and address reuse can break direct attribution. |
| L03 | Was an RDP session established for U on H during W? | RemoteInteractive logons; Terminal Services session events; connection records. | Distinguish authentication, session creation, reconnect and disconnect. One network logon does not establish RDP use. |
| L04 | Was command C executed through WinRM, WMI or another specified remote mechanism? | Mechanism-specific logs; process lineage; source authentication and endpoint records. | winrshost.exe or wmiprvse.exe can be useful clues; lineage or logon type 3 alone does not establish the complete remote chain. |
| L05 | Did U access file F through the specified SMB share during W? | Server-side detailed share/object auditing, including 5145/4663 as configured; client evidence. | Distinguish access checks, requested rights and exercised operations. Share-level access does not identify every file read or copied. |
| L06 | Was U added to privileged group G during W? | Directory/local group-change events; historical group state; actor fields. | Current membership does not date the addition. Separate the account changed from the actor making the change. |
| L07 | Did the observed successful logon follow the specified set of failed attempts? | Authentication records matched by identity, origin and timing. | Temporal sequence does not prove the attempts caused the success; normal retries and shared egress can look similar. |

## 5. Persistence

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| P01 | Was task T configured to launch F at the relevant time? | Task XML; TaskCache; task registration/update events; historical copies. | A schtasks /Create command proves an attempt unless success is established. Current absence does not exclude a deleted task. |
| P02 | Was task T configured to run as the specified principal? | XML Principals/UserId or GroupId; LogonType; RunLevel. | Task author and /RU identify neither a reliable creator nor necessarily the same thing. HighestAvailable is interpreted with the principal; it is not a universal privilege guarantee. |
| P03 | Was task T configured to trigger under condition C? | Triggers; repetition; boundaries; enabled state; settings. | Include logon/startup/event triggers, expiry and missed-run behavior. A recurrence setting does not prove actual runs. |
| P04 | Did task T launch its configured action during W? | Task Scheduler operational records; process creation; action result. | Parent images vary by action and Windows version. A launch does not prove the payload completed successfully. |
| P05 | Was service S configured to start F automatically at the relevant time? | Historical service registry configuration; 7045/4697; change events. | Service installation does not imply automatic start. Check ImagePath, ServiceDll where relevant, Start and account. |
| P06 | Did an autostart entry reference F at the relevant time? | Applicable Run/RunOnce keys; Startup folders; historical hives. | Configuration is distinct from execution. Account scope, registry view and launch conditions matter. |
| P07 | Did a permanent WMI event subscription reference the specified consumer/action? | WMI repository; filter/consumer/binding; Sysmon 19–21 if enabled. | A filter alone is not a complete subscription; configuration does not prove it fired. |
| P08 | Did account U register or modify persistence object O during W? | Task/service/registry audit actor fields; process telemetry; management logs. | Task Author is editable; a service run account and task /RU are execution identities, not creator identities. |

## 6. User activity and devices

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| U01 | Was device N enumerated on H during W? | USB/USBSTOR and device properties; device-event logs; SetupAPI. | Historical enumeration does not automatically place a connection in W. Not every USB storage device follows the same enumeration path. |
| U02 | Is there a validated arrival/removal record for N within W? | Relevant device property timestamps and events; OS-specific interpretation. | Registry last-write and driver installation times are not universal last-connection timestamps. Serials may be absent, generated or duplicated. |
| U03 | Was volume V mounted in account U's context during W? | MountedDevices; MountPoints2; session/device events; historical evidence. | Drive letters and volume labels change. Registry presence may lack a precise mount time. |
| U04 | Does U's profile contain an application-generated reference to F? | Recent LNK; Jump Lists; application MRUs and databases. | This supports recorded interaction according to artifact semantics; it does not by itself establish that the person read the content. |
| U05 | Does a recovered LNK associate F with volume V? | LinkInfo; volume serial; label; target path; available target metadata. | Volume labels are mutable and nonunique; a volume serial is not a hardware USB serial. A link can be stale or copied. |
| U06 | Did application A record opening F during W? | Application history; Jump List interpretation; application/session logs. | Validate AppID mapping and timestamp semantics. A Jump List entry alone may not represent a precisely timed successful open. |
| U07 | Does U's profile record navigation to the specified directory or share? | ShellBags; LNK/Jump Lists; application and server logs. | Directory references do not establish file copying, content viewing or personal intent. |
| U08 | Was content matching F written to device N during W? | Destination file and hash; write telemetry; device/volume mapping; file-system history. | A source-file reference or USB connection alone does not establish copying. Later presence does not by itself date the copy or identify its operator. |

## 7. File systems and recovery

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| F01 | Can bytes attributable to F be recovered from the collected evidence? | File-system metadata; resident data; data runs; carving; snapshots. | A failed carve does not establish wiping. Plain text may lack useful signatures; fragmentation, encryption, TRIM and overwrite affect recovery. |
| F02 | Does E contain a structurally valid volume absent from the current partition table? | Candidate boot structures; backup structures; geometry; file-system consistency. | A candidate signature alone is insufficient. An orphaned volume does not establish that someone deliberately deleted a partition entry. |
| F03 | Does F contain the named non-default NTFS $DATA stream S? | MFT attributes; stream-aware enumeration and extraction. | A named stream is not inherently malicious or truly invisible. Confirm collection preserved streams. |
| F04 | Does recovered stream S contain the specified content or hash? | Extracted stream bytes; length; hash; content analysis. | Separate stream presence, recoverable bytes and interpretation; an empty or partial stream may leave content unresolved. |
| F05 | Is F's $STANDARD_INFORMATION creation time earlier than its $FILE_NAME creation time? | All relevant timestamp attributes; namespace/hard-link context. | A difference is an observation, not proof of timestomping. Equality does not exclude manipulation. |
| F06 | Is F's content inconsistent with its extension? | Headers; internal structure; format-aware parser. | Magic bytes alone can mislead; wrappers and polyglots exist. A mismatch does not establish malicious intent. |
| F07 | Does retained file-system evidence record F being renamed during W? | USN rename old/new records; file reference and sequence; parent references. | Journal wrap and missing pairs limit reconstruction. Paths reconstructed from current metadata may differ from historical paths. |
| F08 | Does retained evidence record a content modification to F during W? | Relevant USN reasons; write telemetry; snapshots/content comparison; MFT. | Metadata timestamps are mutable. USN is not a content history and may coalesce changes; identify the precision available. |
| F09 | Does a recovered deleted-file record still refer to F's original content? | Allocation state; file record sequence; data runs; recovered bytes and validation. | A deleted MFT entry can survive after clusters are reused. Resident content may remain in the MFT rather than unallocated clusters. |
| F10 | Can a carved object's original path be linked to surviving metadata? | Matching hashes/content; MFT/directory entries; application/container metadata. | Carving alone usually loses the file-system path. Correlation may restore it, but a duplicate-content match may not uniquely identify the original location. |

## 8. Memory

Memory acquisition records a changing system over an interval. It can contain historical remnants as well as active state; it is not a perfectly instantaneous or complete snapshot.

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| M01 | Is M correctly identified and parsed for the claimed OS/build? | Acquisition metadata; windows.info; symbol status; structural sanity checks. | Implausible output may reflect missing pages, acquisition inconsistency, wrong symbols or unsupported structures; one plugin's failure does not invalidate every finding. |
| M02 | Does M contain structures corresponding to process instance P? | pslist; psscan; creation/exit times; object addresses. | Pool scans can recover terminated/stale objects. PID alone does not identify a unique process across time. |
| M03 | Does P contain the specified executable private memory region? | VAD metadata; protections; backing; bytes; disassembly; malfind results. | RWX/private memory can be legitimate; injection need not be RWX. A malfind hit is a lead, and a clean result does not exclude injection. |
| M04 | Does the region in P contain code matching the specified payload? | Validated YARA result; byte comparison; disassembly; configuration extraction. | Generic strings or short signatures can match benign data. A match does not show when or by which process the code arrived. |
| M05 | Does endpoint evidence attribute a memory write or remote-thread operation against P to Q? | EDR; suitable Sysmon events such as 8/10 when applicable; source/target instance correlation. | Access rights or process access alone do not prove a write or injection. malfind and parent lineage do not identify the injector by themselves. |
| M06 | Do M's socket structures associate P with endpoint D? | netscan; available network plugins; process lifetime and socket state. | Scanned structures may be stale. Correlate with packet or endpoint evidence before asserting an active connection at acquisition. |
| M07 | Does P's recovered command-line field contain argument A? | cmdline; PEB/process parameters; independent process logs. | The field can be missing, paged out or modified after launch; it is not an immutable execution log. |
| M08 | Is module L absent from a loader list despite being mapped in P? | Loader-list comparisons; VAD/mapped-file analysis; PE validation. | Unlinking is one possibility; loading/unloading, data mappings and acquisition timing are alternatives. List disagreement is not automatically malicious. |
| M09 | Can the in-memory payload be associated with a collected disk object? | PE sections; relocations; unpacked content; hashes where comparable. | A mapped image need not hash identically to its disk file. No disk match in the collection does not prove the attack was fileless. |

## 9. Network

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| N01 | Does the sensor record traffic between A and D on the specified protocol/port during W? | Packets; flow records; five-tuple; address mapping. | Absence is bounded by sensor placement, filters, loss, routing and encryption/tunneling. A port number alone does not identify an application. |
| N02 | Did A send the specified application request to D during W? | Reassembled protocol data; request fields; service logs. | Distinguish a request from retransmissions, responses and successful processing. For HTTP, record a valid filter such as `http.request && http.request.uri contains "/checkin"`. |
| N03 | Do requests to D meet a stated periodicity criterion over W? | Request timestamps; interval distribution; sample count; recorded threshold. | Define the criterion before interpreting it. Regularity can be benign; jittered or irregular traffic can still be C2. |
| N04 | Does the captured TLS ClientHello contain server name S? | Parsed SNI from the relevant handshake. | SNI identifies a presented name, not validated ownership or ultimate content. ECH, missing packets or absent SNI may conceal it. |
| N05 | Does reconstructed plaintext session S contain the specified file content? | Reassembled bytes; extracted object; hash; authorized TLS decryption when available. | Encrypted traffic may be readable with suitable keys. Without plaintext or reliable endpoint evidence, content may remain unknown. |
| N06 | Does session S contain more than the stated quantity of A-to-D data? | Defined measurement: frame bytes, transport payload or unique application bytes. | Record direction, layer, retransmission treatment and capture loss. Wire bytes are not automatically uploaded file size. |
| N07 | Did A probe the specified set of hosts/ports during W? | Destination distribution; connection attempts; protocol behavior. | Scanning may succeed or fail. Discovery protocols can be legitimate or abused; broadcast traffic is not automatically irrelevant noise. |
| N08 | Does endpoint telemetry link the observed network connection to P? | Sysmon 3; EDR network records; matching endpoints, time and process instance. | 4688 alone lacks network attribution; SRUM provides usage context rather than a general five-tuple connection log. |
| N09 | Is capture S sufficiently complete for the proposed reconstruction? | TCP sequence gaps; handshake/closure; snap length; drop statistics; sensor topology. | SYN and FIN plus file start/end times do not prove completeness. Missing closure can be normal; UDP has no TCP handshake. |
| N10 | Did resolver R record a query for domain S from A during W? | DNS packets; resolver logs; endpoint DNS events. | A query does not prove a connection. Cache hits, DoH, shared resolvers and missing visibility can explain absent queries. |

## 10. Manipulation and anti-forensics

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| T01 | Does telemetry record a process changing F's creation timestamp during W? | Sysmon 2; comparable EDR records; old/new values; process identity. | A timestamp change is not intent. Copying, installation and restoration can legitimately set times; Sysmon 2 does not cover all timestamp changes. |
| T02 | Was Windows event channel C explicitly cleared during W? | Security 1102; applicable Eventlog 104 records in System; forwarded copies. | A retained clear event supports clearing, not malicious attribution. Its absence does not exclude clearing or offline modification. |
| T03 | Does a retention or collection change account for the observed log gap? | Channel policy/history; collector health; archived logs; forwarder status. | A plausible explanation is not necessarily established; compare timing and expected effects. More than one cause may contribute. |
| T04 | Did P perform overwrite operations against the specified file/device range? | Suitable write telemetry; tool output; before/after bytes; affected ranges. | Zeroed space alone does not identify a wipe. TRIM, initialization, sparse allocation and acquisition substitutions may explain the observation. |
| T05 | Does stream S contain executable content rather than the claimed origin metadata? | Actual stream bytes; parsing; payload structure. | Stream names are arbitrary. A stream named Zone.Identifier can be manipulated; judge content and use, not the name alone. |
| T06 | Is F a valid instance of the claimed compressed or encrypted format? | Container structure; format-aware tools; successful decoding/decryption if possible. | High entropy alone distinguishes neither compression from encryption nor benign from malicious content. |
| T07 | Was the audit or security sensor configuration changed during W? | Historical policies; configuration-change records; management/EDR logs. | Current disabled state does not date a change or identify its actor. Distinguish authorized maintenance from hostile interference. |

## 11. Staging, exfiltration and impact

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| X01 | Was archive X created on H during W? | File creation; archiver telemetry; archive metadata/content; historical snapshots. | A command can fail. Creation time can be copied or changed; archive presence is not exfiltration. |
| X02 | Does archive X contain the specified sensitive files? | Extracted archive entries; recovered contents; hashes or validated content matches. | An archive command listing paths proves neither inclusion nor successful reads. An encrypted unavailable archive may prevent confirmation. |
| X03 | Did P attempt to upload X to D during W? | Command/script; application logs; endpoint network telemetry; requests. | An attempt is distinct from completion. A network connection alone does not identify the uploaded object. |
| X04 | Did destination D accept content matching X during W? | Receiver object/audit records; hashes; validated application response; reconstructed transfer. | Receiver evidence is valuable but not universally available or mandatory. Sender-side plaintext transfer and trustworthy success evidence may support completion; encrypted byte totals alone do not. |
| X05 | Is D outside the organization's authorized destination set at the relevant time? | Historical tenant/account ownership; business approvals; service configuration. | An external cloud domain may host an authorized account. Unauthorized transfer and malicious intent are separate conclusions. |
| X06 | Was F's content changed in the impact interval? | Before/after content; snapshots; write records; file-system history. | Modification-time clustering helps triage but does not establish every changed file or the responsible process. |
| X07 | Were the specified files renamed with suffix E during W? | Rename telemetry; USN pairs; historical directory listings. | A suffix does not establish encryption. Ransomware may preserve extensions or timestamps. |
| X08 | Did F change from readable content to an encrypted representation during W? | Known-good comparison; content structure; validated transformation; process telemetry. | Corruption and compression can resemble encryption. Ransom notes and entropy alone are insufficient. |
| X09 | Was ransom-note file R created on H during W? | Recovered content; file events; historical copies. | A note can be copied by a responder or planted without encryption. Date it and identify its creator where possible. |
| X10 | Does the collected evidence show the specified unaffected file set retained its content through W? | Before/after hashes; snapshots; monitoring coverage. | Directory timestamps do not establish that child files were unaffected. Define the set and coverage rather than asserting an entire directory was spared. |
| X11 | Did P attempt to delete or disable the specified backup/snapshot resource? | Commands; script content; backup management/API audit logs. | A deletion command proves an attempt, not success. Existing snapshots do not exclude deletion of other snapshots or subsequent recreation. |
| X12 | Was backup resource B deleted or made unusable during W? | Backup catalog history; provider logs; resource state; validated restore results. | Current absence alone does not date deletion or establish cause. Distinguish deletion, access denial, encryption and failed restore. |
| X13 | Did service S become unavailable for the claimed interval? | External monitoring; application logs; dependency status; recovery records. | File encryption does not quantify downtime or financial loss. Differentiate technical outage from measured business impact. |

## 12. Reporting and challenge

| ID | Testable question | Evidence to examine | Challenges and limits |
|---|---|---|---|
| R01 | Can another examiner reproduce observation O from the preserved exhibit? | Exhibit/hash; artifact path; record ID or offset; query; tool/version/settings. | Reproducing a parser output does not independently validate its interpretation. Resolve important anomalies against raw data or another method. |
| R02 | Does the proposed event ordering survive measured timestamp uncertainty? | Timeline with offsets, granularity and error bounds. | If plausible clock corrections reverse the order, report the ordering as uncertain. |
| R03 | Can the specified activity be associated with an authorized responder operation? | Responder command records; time; account/session; tool hash; target. | Activity after collection began is not automatically responder activity, and response activity may precede formal collection. |
| R04 | Is sequence S rare relative to the defined comparison population? | Fleet-wide query; denominator; time window; collection coverage. | Rarity does not establish malice; common behavior can still be abused. A biased baseline produces misleading rarity. |
| R05 | Does alternative explanation A account for all material observations used to support claim C? | Competing predictions; supporting and contradictory records. | Do not select an alternative merely because it is possible. Identify distinguishing observations and unresolved gaps. |
| R06 | Is the claim about a person supported beyond account/device association? | Session evidence; independently verified access circumstances; other relevant evidence. | Account ownership and device possession alone may be insufficient. Explain the strength and limits of attribution rather than assuming it is impossible or established. |

## Worked examples

These scenarios are illustrative, not universal artifact recipes.

### 1. “The attacker ran the executable.”

**Break it down:** Did the identified file execute? Under which process instance and security context? What connects that instance to the suspected intrusion?

**Bounded hypothesis:** A process of SHA-256 `HASH-F` started on `WS-01` between 09:00 and 10:00 UTC.

**Test:** Search retained process-creation records for that host and interval; verify path and hash where recorded. Use Prefetch and related artifacts as appropriate, with OS-specific semantics. Establish historical collection coverage.

**Challenge:** The similarly named process record has a different hash. It does not support execution of `HASH-F`. If other executions are not fully covered, the broader execution claim remains unresolved.

**Defensible result:** “Sysmon Event 1 records a process matching `HASH-F` starting at 09:14 UTC under account U. This establishes recorded process creation; it does not by itself identify the human operator or show successful completion.”

### 2. “No execution artifacts means it never ran.”

**Bounded hypothesis:** F executed during W.

**Observation:** No Prefetch or matching process-creation event was recovered.

**Coverage check:** Prefetch was disabled and retained process logs begin after W.

**Defensible result:** “Execution during W cannot be determined from the collected sources.” Do not label this a falsification.

If a controlled validation shows the exact behavior reliably generates a retained record under the relevant configuration, a negative search becomes stronger evidence against the hypothesis. Record the assumptions and residual blind spots; two empty searches alone do not create that assurance.

### 3. “The USB device was used to steal files.”

**Separate hypotheses:** Device N was connected during W; volume V belongs to N; content matching F was written to V during W; that transfer was unauthorized; a particular person performed it.

**Test:** Correlate validated device arrival records, volume mappings, destination content/hash and write/history evidence. Review authorization and operator attribution separately.

**Challenge:** The LNK identifies another volume, or the recovered destination file differs from F. A device connection without destination evidence leaves the copying claim unresolved.

**Defensible result:** “Device N was connected during W, and U's profile contains a reference to F. The collected evidence does not establish that F was copied to N.”

### 4. “The network capture proves exfiltration.”

**Bounded hypothesis:** Archive X was successfully uploaded from H to the specified external account D during W.

**Test:** Establish X's contents, associate the transfer with X, inspect reassembled application data or endpoint/service logs, determine completion and resolve destination account ownership.

**Challenge:** A reliable server response rejects the particular request, with no evidence of a retry. This contradicts completion of that request, not every possible transfer during W.

**Defensible result when encrypted:** “H sent approximately N transport-payload bytes to D. The capture does not reveal the object content or establish that X was accepted.” Sender or receiver evidence may resolve the gap.

### 5. “malfind proves Meterpreter migration.”

**Separate hypotheses:** Process P contains suspicious executable memory; the region contains the specified payload; process Q placed that code in P.

**Test:** Inspect VAD protections/backing and recovered bytes; validate payload-specific matches; correlate source/target telemetry and available session records.

**Challenge:** The region is explained by a known JIT runtime. This challenges malicious interpretation of that region. Other injection techniques remain possible elsewhere.

**Defensible result:** “P contains a private executable region with bytes matching the validated payload signature. The collected evidence does not identify the injecting process.” Neither an RWX region nor an unlinked module alone proves migration.

## Investigation worksheet

Copy this block for each material hypothesis:

```text
Question ID:
Investigative question:
Bounded hypothesis:
Host / account / process instance / file identity:
Time window and timestamp uncertainty:
Why this matters to the investigation:
Expected observations if the hypothesis is correct:
Observations that would challenge the hypothesis:
Evidence sources and exact locations:
Coverage, retention and relevant configuration:
Tool versions, settings and exact query/filter:
Observed results, including contrary observations:
Alternative explanations and distinguishing tests:
Outcome: Supported / Contradicted / Unresolved
Confidence and reasons:
Limitations and next evidence needed:
Report wording:
```

Use confidence to explain evidence quality, directness, coverage and competing explanations. Avoid invented numeric probabilities. Revisit an outcome when additional evidence arrives.

## Technical references

Artifact behavior depends on OS, application, configuration and tool version. Validate consequential interpretations in a representative lab where feasible. These sources support specific technical details; the question bank and reporting framework are an editorial synthesis, not an official INE, Microsoft or NIST standard.

- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final) — collection, examination, analysis and reporting framework.
- [Microsoft: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — event semantics, including process creation, creation-time changes, network connections and WMI subscription events. Configuration affects available evidence.
- [Microsoft Incident Response: Leveraging Windows Internals for Forensic Investigation](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf) — interpretation and limitations of Windows artifacts, including Amcache and ShimCache.
- [Microsoft: Shell Link binary format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) and [VolumeID structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a) — link target and volume fields.
- [Volatility 3 documentation](https://volatility3.readthedocs.io/) and [project source](https://github.com/volatilityfoundation/volatility3) — plugin behavior and version-specific implementation. Check the installed version rather than assuming a plugin name or detection rule is timeless.

