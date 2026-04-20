# CodeSentinel Evaluation Summary
Timestamp: 20260420_031752
Samples: 10

## Single-prompt Baseline
- TPR: 0.75
- FPR: 0.0
- CWE Accuracy: 1.0
- TP=6, FP=0, FN=2

## Multi-agent CodeSentinel
- TPR: 1.0
- FPR: 0.0
- CWE Accuracy: 1.0
- TP=8, FP=0, FN=0

## Delta (multi - baseline)
- TPR: +0.250
- FPR: +0.000
- CWE Accuracy: +0.000

## McNemar's Exact Test (paired per-sample)
- Samples where only baseline detected all GT findings (b_only): 0
- Samples where only multi-agent detected all GT findings (m_only): 2
- Both systems detected all: 6
- Neither detected all (or no GT): 2
- Discordant pairs: 2
- Two-sided exact p-value: 0.5000
- Result: observed direction favors multi-agent, but with only 2 discordant pair(s) the test cannot reach conventional significance (p>0.05). A run against a larger suite would be required to claim statistical superiority.