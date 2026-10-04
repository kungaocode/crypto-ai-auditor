# Round 5 Final Dataset — Quality Assurance Report

**Total new samples**: 148 (detect=93 triage=55)
**Overall QA**: FAIL

## Checks
- ✅ **duplicate_ids**: 0
- ✅ **missing_fields**: 0
- ✅ **syntax_errors**: 0
- ✅ **label_conflicts**: 0
- ✅ **split_leakage**: 0
- ❌ **backtest_pos_missing**: 22
- ✅ **backtest_aneg_hit**: 0
- ❌ **backtest_bneg_no_fire**: 25

## Rule Coverage
- ✅ **CRYPTO-001**: detect=5 triage=13
- ✅ **CRYPTO-002**: detect=6 triage=7
- ✅ **CRYPTO-003**: detect=3 triage=4
- ✅ **CRYPTO-004**: detect=1 triage=2
- ✅ **CRYPTO-005**: detect=2 triage=1
- ✅ **CRYPTO-006**: detect=1 triage=1
- ✅ **CRYPTO-007**: detect=1 triage=1
- ✅ **CRYPTO-008**: detect=1 triage=1
- ✅ **CRYPTO-009**: detect=4 triage=2
- ✅ **CRYPTO-010**: detect=4 triage=2
- ✅ **CRYPTO-011**: detect=16 triage=8
- ✅ **CRYPTO-012**: detect=20 triage=6
- ✅ **CRYPTO-013**: detect=19 triage=7

## Split Distribution
- **split_test**: detect=17 triage=20
- **split_train**: detect=66 triage=26
- **split_val**: detect=10 triage=9

## Detect Source Distribution
- round5-adhoc-crypto-009: 4 (pos=2 neg=2)
- round5-adhoc-crypto-010: 4 (pos=2 neg=2)
- round5-known-kdf-params-aneg: 7 (pos=0 neg=7)
- round5-known-kdf-params-bneg: 4 (pos=0 neg=4)
- round5-known-kdf-params-pos: 7 (pos=7 neg=0)
- round5-known-password-storage-aneg: 4 (pos=0 neg=4)
- round5-known-password-storage-bneg: 5 (pos=0 neg=5)
- round5-known-password-storage-pos: 7 (pos=7 neg=0)
- round5-known-timing-compare-aneg: 7 (pos=0 neg=7)
- round5-known-timing-compare-bneg: 5 (pos=0 neg=5)
- round5-known-timing-compare-pos: 6 (pos=6 neg=0)
- round5-libaudit-detect-aneg: 10 (pos=0 neg=10)
- round5-libaudit-detect-bneg: 11 (pos=0 neg=11)
- round5-libaudit-detect-pos: 12 (pos=12 neg=0)

## Triage Source Distribution
- round5-adhoc-crypto-009: 2 (Confirm=1 Reject=1)
- round5-adhoc-crypto-010: 2 (Confirm=1 Reject=1)
- round5-known-kdf-params-tneg: 4 (Confirm=0 Reject=4)
- round5-known-kdf-params-tpos: 2 (Confirm=2 Reject=0)
- round5-known-password-storage-tneg: 6 (Confirm=0 Reject=6)
- round5-known-password-storage-tpos: 2 (Confirm=2 Reject=0)
- round5-known-timing-compare-tneg: 4 (Confirm=0 Reject=4)
- round5-known-timing-compare-tpos: 2 (Confirm=2 Reject=0)
- round5-libaudit-triage-confirm: 8 (Confirm=8 Reject=0)
- round5-libaudit-triage-reject: 12 (Confirm=0 Reject=12)
- round5-passlib-legacy: 11 (Confirm=0 Reject=11)

## Held-out Test Samples (for eval)
- `r5-001-pos-02` (detect, CRYPTO-001, vuln=True verdict=?)
- `r5-003-pos-01` (detect, CRYPTO-005, vuln=True verdict=?)
- `r5-004-pos-01` (detect, CRYPTO-004, vuln=True verdict=?)
- `r5-006-pos-01` (detect, CRYPTO-006, vuln=True verdict=?)
- `r5-008-pos-01` (detect, CRYPTO-008, vuln=True verdict=?)
- `r5-009-pos-01` (detect, CRYPTO-009, vuln=True verdict=?)
- `r5-009-tneg-01` (triage, CRYPTO-009, vuln=? verdict=Reject)
- `r5-009-tpos-01` (triage, CRYPTO-009, vuln=? verdict=Confirm)
- `r5-010-pos-01` (detect, CRYPTO-010, vuln=True verdict=?)
- `r5-010-tneg-01` (triage, CRYPTO-010, vuln=? verdict=Reject)
- `r5-011-bneg-01` (detect, CRYPTO-011, vuln=False verdict=?)
- `r5-011-tpos-01` (triage, CRYPTO-011, vuln=? verdict=Confirm)
- `r5-012-bneg-02` (detect, CRYPTO-012, vuln=False verdict=?)
- `r5-012-pos-02` (detect, CRYPTO-012, vuln=True verdict=?)
- `r5-012-tneg-01` (triage, CRYPTO-012, vuln=? verdict=Reject)
- `r5-012-tpos-02` (triage, CRYPTO-012, vuln=? verdict=Confirm)
- `r5-013-pos-01` (detect, CRYPTO-013, vuln=True verdict=?)
- `r5-bneg-des-crypt` (detect, CRYPTO-003, vuln=False verdict=?)
- `r5-bneg-itsdangerous-sha1` (detect, CRYPTO-002, vuln=False verdict=?)
- `r5-bneg-test-md5-kat` (detect, CRYPTO-001, vuln=False verdict=?)
- `r5-tconf-des-pii` (triage, CRYPTO-003, vuln=? verdict=Confirm)
- `r5-tconf-hardcoded-key` (triage, CRYPTO-007, vuln=? verdict=Confirm)
- `r5-tconf-rc4-stream` (triage, CRYPTO-004, vuln=? verdict=Confirm)
- `r5-tconf-sha1-password` (triage, CRYPTO-002, vuln=? verdict=Confirm)
- `r5-tconf-static-iv` (triage, CRYPTO-006, vuln=? verdict=Confirm)
- `r5-test-011-bneg` (detect, CRYPTO-011, vuln=False verdict=?)
- `r5-test-011-tneg` (triage, CRYPTO-011, vuln=? verdict=Reject)
- `r5-test-012-bneg` (detect, CRYPTO-012, vuln=False verdict=?)
- `r5-test-012-tneg` (triage, CRYPTO-012, vuln=? verdict=Reject)
- `r5-test-013-bneg` (detect, CRYPTO-013, vuln=False verdict=?)
- `r5-test-013-tneg` (triage, CRYPTO-013, vuln=? verdict=Reject)
- `r5-trej-test-des3` (triage, CRYPTO-003, vuln=? verdict=Reject)
- `round5-passlib-passlib_handlers_cisco__cisco_pix__calc_checksum-CRYPTO-001` (triage, CRYPTO-001, vuln=? verdict=Reject)
- `round5-passlib-passlib_handlers_django__django_salted_sha1__calc_checksum-CRYPTO-002` (triage, CRYPTO-002, vuln=? verdict=Reject)
- `round5-passlib-passlib_handlers_mysql__mysql41__calc_checksum-CRYPTO-002` (triage, CRYPTO-002, vuln=? verdict=Reject)
- `round5-passlib-passlib_handlers_postgres__postgres_md5__calc_checksum-CRYPTO-001` (triage, CRYPTO-001, vuln=? verdict=Reject)
- `round5-passlib-passlib_handlers_sun_md5_crypt__raw_sun_md5_crypt-CRYPTO-001` (triage, CRYPTO-001, vuln=? verdict=Reject)
