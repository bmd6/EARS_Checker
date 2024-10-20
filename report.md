# EARS Syntax Compliance Report

## Requirement 1
**Text:** The mobile phone shall have a mass of less than 150 grams.

**Status:** ✅ Compliant

**EARS Pattern:** Response, Ubiquitous

---

## Requirement 2
**Text:** While there is no card in the ATM, the ATM shall display “insert card to begin”.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (State Driven, Response)

---

## Requirement 3
**Text:** When “mute” is selected, the laptop shall suppress all audio output.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (Event Driven, Response)

---

## Requirement 4
**Text:** If an invalid credit card number is entered, then the website shall display “please re-enter credit card details”.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (Unwanted Behavior, Response)

---

## Requirement 5
**Text:** The system respond to user input.

**Status:** ❌ Non-compliant

**Recommendation:** Add the keyword 'shall' to specify the system response. Example:
  'When <trigger>, the <system name> shall <system response>.'

---

## Requirement 6
**Text:** If withdrawal request exceeds balance, then the ATM shall display “balance exceeded”

**Status:** ❌ Non-compliant

**Recommendation:** The requirement structure does not match any EARS pattern. Please revise accordingly.

---

## Requirement 7
**Text:** If the computed airspeed fault flag is set, then the control system shall use modelled airspeed.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (Unwanted Behavior, Response)

---

## Requirement 8
**Text:** While the aircraft is in-flight, the control system shall maintain engine fuel flow above XXlbs/sec

**Status:** ❌ Non-compliant

**Recommendation:** The requirement structure does not match any EARS pattern. Please revise accordingly.

---

## Requirement 9
**Text:** The kitchen system shall have an input hatch.

**Status:** ✅ Compliant

**EARS Pattern:** Response, Ubiquitous

---

## Requirement 10
**Text:** When the chef inserts a potato to the input hatch, the kitchen system shall peel the potato.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (Event Driven, Response)

---

## Requirement 11
**Text:** While the kitchen system is in maintenance mode, the kitchen system shall reject all input.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (State Driven, Response)

---

## Requirement 12
**Text:** If a spoon is inserted to the input hatch, then the kitchen system shall eject the spoon.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (Unwanted Behavior, Response)

---

## Requirement 13
**Text:** Where the kitchen system has a food freshness sensor, the kitchen system shall detect rotten foodstuffs.

**Status:** ✅ Compliant

**EARS Pattern:** Complex (Optional Feature, Response)

---

## Summary
- **Total Requirements:** 13
- **EARS Compliant:** 10
- **Non-compliant:** 3

### Requirements per EARS Pattern
- **Response:** 10
- **Ubiquitous:** 2
- **State Driven:** 2
- **Complex:** 8
- **Event Driven:** 2
- **Unwanted Behavior:** 3
- **Optional Feature:** 1
