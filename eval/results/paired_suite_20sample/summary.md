# CodeSentinel Evaluation Summary
Timestamp: 20260420_031730
Samples: 20

## Single-prompt Baseline
- TPR: 0.333
- FPR: 0.571
- CWE Accuracy: 1.0
- TP=3, FP=4, FN=6

## Multi-agent CodeSentinel
- TPR: 1.0
- FPR: 0.182
- CWE Accuracy: 1.0
- TP=9, FP=2, FN=0

## Delta (multi - baseline)
- TPR: +0.667
- FPR: -0.389
- CWE Accuracy: +0.000

## McNemar's Exact Test (paired per-sample)
- Samples where only baseline detected all GT findings (b_only): 0
- Samples where only multi-agent detected all GT findings (m_only): 6
- Both systems detected all: 3
- Neither detected all (or no GT): 11
- Discordant pairs: 6
- Two-sided exact p-value: 0.0312
- Result: direction favors multi-agent, p <= 0.05.