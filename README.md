# CSCI262 Assignment 3 – Email IDS

**Group report (Google Doc):** https://docs.google.com/document/d/1RpkE0uu0vqTtY-2W4dwvMbLjEPAiLTfO/edit?usp=sharing&ouid=108559256656279093968&rtpof=true&sd=true

An email system event modeller and intrusion detection system. It simulates normal email activity, learns a baseline from it, then flags days of new activity that deviate too far from that baseline.

## Requirements

- Python 3.8 or later. Nothing needs installing: it uses the standard library only.

## Running

From this folder:

```
python IDS.py Events.txt Stats.txt 100          # 100-day baseline, different data every run
python IDS.py Events.txt Stats.txt 100 262      # same, but reproducible (seed 262)
```

On macOS/Linux use `python3` if `python` isn't found.

The program reads the two input files, generates and analyses the baseline, then asks two questions in a loop:

1. **Statistics file for live data:** e.g. `test_inputs/LiveStats_attack.txt`
2. **Number of days to generate:** e.g. `10`

For each live day it prints the anomaly counter and whether the day is `okay` or `FLAGGED`. Enter `q` at either prompt to quit.

## Test inputs

| File | What it tests | Expected |
|---|---|---|
| `test_inputs/LiveStats_normal.txt` | Same as `Stats.txt` | No days flagged |
| `test_inputs/LiveStats_mixed.txt` | Moderately higher activity | Occasional days flagged |
| `test_inputs/LiveStats_attack.txt` | Large increase in activity | Every day flagged |
| `test_inputs/Stats_inconsistent.txt` | Use as the 2nd command-line argument | Error: missing/unknown event, mean out of range |
| `test_inputs/Stats_warnings.txt` | Use as the 2nd command-line argument | Warnings, but the program still runs |

With seed 262, entering normal (10 days), mixed (12 days), then attack (8 days) reproduces the report's figures exactly: 0 of 10, 1 of 12 and 8 of 8 days flagged.

## Output

Each run writes to `output/` (not tracked in git; it's recreated every run and overwrites the previous files):

| File | Written by | Contents |
|---|---|---|
| `baseline_log.txt`, `liveN_log.txt` | Activity engine | One line per event: `day \| time \| event \| value` |
| `baseline_totals.txt`, `liveN_totals.txt` | Analysis engine | Daily totals, then the mean and std dev per event |

## How it works

1. **Initial input** reads and cross-checks `Events.txt` and `Stats.txt`.
2. **Activity engine** draws each day's total per event from a normal distribution (mean and std dev from the stats file) and logs individual events.
3. **Analysis engine** reads the log back and computes daily totals, mean and sample std dev. For the first run this is the baseline.
4. **Alert engine** scores each live day: the sum over events of `weight × |total − baseline mean| / baseline std dev`. A day is flagged if that is ≥ `2 × sum of weights` (18 with the supplied `Events.txt`).
