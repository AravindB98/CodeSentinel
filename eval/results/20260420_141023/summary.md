# CodeSentinel Evaluation Summary
Timestamp: 20260420_141023
Samples: 10

## Single-prompt Baseline
- TPR: 1.0
- FPR: 0.8
- CWE Accuracy: 1.0
- TP=8, FP=32, FN=0

## Multi-agent CodeSentinel
- TPR: 0.0
- FPR: 0.0
- CWE Accuracy: 0.0
- TP=0, FP=0, FN=8

## Delta (multi - baseline)
- TPR: -1.000
- FPR: -0.800
- CWE Accuracy: -1.000

## McNemar's Exact Test (paired per-sample)
- Samples where only baseline detected all GT findings (b_only): 8
- Samples where only multi-agent detected all GT findings (m_only): 0
- Both systems detected all: 0
- Neither detected all (or no GT): 2
- Discordant pairs: 8
- Two-sided exact p-value: 0.0078
- Result: direction favors baseline, p <= 0.05.