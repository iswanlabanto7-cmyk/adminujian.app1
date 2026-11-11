# Security Specification for Firestore Rules

## 1. Data Invariants
- An exam document (`/data_ujian/{examId}`) must have a valid string `namaUjian` (max length 200).
- An exam document must contain a valid URL string `linkGoogleForm` (max length 500).
- PIN fields (`pinMasuk`, `pinKeluar`, `pinPengawas`) must be alphanumeric strings between 1 and 20 characters.
- `zonaWaktu` must strictly be one of `['WIB', 'WITA', 'WIT']`.
- Document ID path variable `{examId}` must be a valid alphanumeric/hyphen/underscore identifier up to 128 characters.
- Anyone can read exam sessions (or student app scanning the QR code with examId to get Google Form and verify PINs), while creation requires valid structural schemas.

## 2. The Dirty Dozen Payloads (12 Malicious/Invalid Scenarios)
1. **Ghost Field Injection**: Payload contains extra unexpected key `adminBypass: true`.
2. **Oversized Exam Name**: Payload contains `namaUjian` exceeding 200 characters (Denial of Wallet).
3. **Invalid Time Zone**: Payload contains `zonaWaktu: "GMT+7"` (not in WIB/WITA/WIT).
4. **Empty PIN Masuk**: Payload contains empty string `pinMasuk: ""`.
5. **Oversized PIN**: Payload contains 1000-character string for `pinPengawas`.
6. **Path Traversal / Malicious ID**: Request uses doc ID containing `../../malicious_path`.
7. **Type Poisoning**: `namaUjian` passed as a boolean `true` instead of a string.
8. **Missing Required Field**: Payload missing `linkGoogleForm`.
9. **Invalid Protocol/Link**: `linkGoogleForm` passed as numeric integer `12345`.
10. **Array Injection**: `zonaWaktu` passed as an array `["WIB", "WIT"]`.
11. **Null Payload**: Creation attempt with empty null payload.
12. **Tampered Immutability**: Attempt to rewrite document id or corrupted timestamps.

## 3. Test Runner Specification
Tests verify that all 12 dirty payloads are rejected with `PERMISSION_DENIED`.
