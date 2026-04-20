# CodeSentinel Evaluation Summary
Timestamp: 20260420_143220
Samples: 10

## Single-prompt Baseline
- TPR: 1.0
- FPR: 0.789
- CWE Accuracy: 1.0
- TP=8, FP=30, FN=0

## Multi-agent CodeSentinel
- TPR: 1.0
- FPR: 0.111
- CWE Accuracy: 1.0
- TP=8, FP=1, FN=0

## Delta (multi - baseline)
- TPR: +0.000
- FPR: -0.678
- CWE Accuracy: +0.000

## McNemar's Exact Test (paired per-sample)
- Samples where only baseline detected all GT findings (b_only): 0
- Samples where only multi-agent detected all GT findings (m_only): 0
- Both systems detected all: 8
- Neither detected all (or no GT): 2
- Discordant pairs: 0
- No discordant pairs: test not applicable.