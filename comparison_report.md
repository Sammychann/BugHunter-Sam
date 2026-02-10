# Comparison Report: Ground Truth vs Generated Explanations

| ID | Status | Ground Truth Explanation | Generated Explanation |
|---|---|---|---|
| 101 | ✅ Detected | BUG: vecEditMode must be VTT when runtime label copy is used. VECD causes undefined behavior. | Wrong vector edit mode: when copyLabel() is used, vecEditMode must be TA::VTT, not TA::VECD. VTT mode is required for label-based vector editing. |
| 102 | ⚠️ Default | BUG: execute() is missing after DC force setup. | Potential API misuse detected in code snippet. |
| 103 | ✅ Detected | BUG: iClamp limits reversed, causing clamp overflow. | iClamp argument order error: iClamp(20.0, -20.0) has low and high values exchanged. First argument should be the low clamp, second should be high. Correct: iClamp(-20.0, 20.0). |
| 104 | ✅ Detected | BUG: Using read() instead of execute() in measurement chain. | Wrong terminal method: 'read()' should be 'execute()' in this RDI measurement chain. DC and func operations require .execute() to complete. |
| 105 | ⚠️ Default | BUG: Missing RDI_BEGIN before runtime protocol write. | Potential API misuse detected in code snippet. |
| 106 | ✅ Detected | BUG: getAlarmValue() called without specifying pin name. | Missing parameter: getAlarmValue() requires a pin name string parameter. |
| 107 | ✅ Detected | BUG: Incorrect function casing imeas() instead of iMeas(). | Incorrect function name: '.imeas()' should be '.iMeas()'. This is a known API naming error. |
| 108 | ✅ Detected | BUG: burstUpload end called with wrong scope. | Incorrect chain order: 'rdi.burstUpload.smartVec()' should be 'rdi.smartVec().burstUpload()'. burstUpload() is a method of smartVec, not the other way around. |
| 109 | ✅ Detected | BUG: Pin name mismatch between capture and retrieval. | Pin name mismatch: pin 'D1' in setup (line 1) does not match 'DI' in retrieval (line 2). These look like they should be the same pin (possible typo: 'D1' vs 'DI'). |
| 110 | ✅ Detected | BUG: readTempThresh() does not take parameters. | Extra parameter: readTempThresh() takes no parameters. Remove the argument to fix this API call. |
| 111 | ✅ Detected | BUG: vForce exceeds configured voltage range. | Range overflow: vForce(31.0 V) exceeds vForceRange(30.0 V). The programmed force value must always match the selected range to avoid range overflow warnings. |
| 112 | ⚠️ Default | BUG: Missing execute() after waveform chaining. | Potential API misuse detected in code snippet. |
| 113 | ✅ Detected | BUG: push_forward() API removed. Use push_back(). | Incorrect function name: '.push_forward()' should be '.push_back()'. This is a known API naming error. |
| 114 | ✅ Detected | BUG: retrievePmuxPinStatus called before transaction end. | Scope violation: retrievePmuxPinStatus() should be called after RDI_END(), not inside the RDI_BEGIN/RDI_END block. Status retrieval requires the execution block to complete first. |
| 115 | ✅ Detected | BUG: digCapBurstSiteUpload disabled while requesting upload. | digCapBurstSiteUpload should be set to true for uploads. Currently set to false, should be true. |
| 116 | ✅ Detected | BUG: Sample count exceeds maximum supported limit. | Sample count 9000 exceeds maximum allowed value of 8192. |
| 117 | ✅ Detected | BUG: getFFV() replaced incorrectly with getFFC(). | Invalid function name 'getFFC()' — this appears to be a corrupted API name. The closest valid function is 'getFFV()'. |
| 118 | ⚠️ Default | BUG: Wrong readMode used for digital capture. | Potential API misuse detected in code snippet. |
| 119 | ⚠️ Default | BUG: Missing RDI_END leads to session leakage. | Potential API misuse detected in code snippet. |
| 120 | ⚠️ Default | BUG: Port name mismatch between initialization and runtime. | Potential API misuse detected in code snippet. |
