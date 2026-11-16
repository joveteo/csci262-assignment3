#!/usr/bin/env python3
"""
CSCI262 Assignment 3 - Email system event modeller and intrusion detection system.

Usage:
    python IDS.py Events.txt Stats.txt Days [seed]

The optional integer seed makes a run reproducible; without it every run differs.

The program runs four components in order:
    1. Initial input    - read and validate Events.txt and Stats.txt
    2. Activity engine  - simulate <Days> days of events and write them to a log
    3. Analysis engine  - read the log back, compute daily totals, mean and std dev
    4. Alert engine     - repeatedly read a new stats file and a number of days,
                          simulate "live" data and flag days that look anomalous
"""

import math
import os
import random
import re
import statistics
import sys

OUTPUT_DIR = "output"
SECONDS_PER_DAY = 24 * 60 * 60
MAX_REDRAWS = 1000            # attempts to draw a daily total inside [min, max]
MAX_SESSIONS_PER_DAY = 5      # a continuous daily total is split into 1..5 sessions
MAX_PROGRESS_LINES = 10       # progress messages per activity engine run
QUIT_WORDS = ("q", "quit", "exit")
USAGE = "Usage: python IDS.py Events.txt Stats.txt Days [seed]"


class InputError(Exception):
    """An input file is missing, malformed or inconsistent with another file."""


# =============================================================================
# Data model
# =============================================================================

class Event:
    """One monitored event type, as described by a line of Events.txt."""

    def __init__(self, name, kind, minimum, maximum, weight):
        self.name = name          # display name, exactly as written in the file
        self.kind = kind          # "C" (continuous) or "D" (discrete)
        self.minimum = minimum
        self.maximum = maximum    # math.inf when the file leaves it blank
        self.weight = weight

    @property
    def is_discrete(self):
        return self.kind == "D"

    @property
    def resolution(self):
        """Smallest change that can be recorded: 1 for discrete, 0.01 for continuous."""
        return 1 if self.is_discrete else 0.01

    def format_value(self, value):
        """Discrete values as integers, continuous values to two decimal places."""
        if self.is_discrete:
            return str(int(round(value)))
        return f"{value:.2f}"

    def format_maximum(self):
        if math.isinf(self.maximum):
            return "no limit"
        return self.format_value(self.maximum)


class Stat:
    """Distribution for one event, as described by a line of a stats file."""

    def __init__(self, name, mean, std):
        self.name = name
        self.mean = mean
        self.std = std


def normalise_name(name):
    """Lookup key for an event: lower case, with runs of whitespace collapsed."""
    return re.sub(r"\s+", " ", name.strip()).lower()


def round_up_to_cents(value):
    """Smallest two-decimal value >= value (tolerant of float noise like 0.1 + 0.2)."""
    return math.ceil(round(value * 100, 6)) / 100


def round_down_to_cents(value):
    """Largest two-decimal value <= value; infinity stays infinity."""
    if math.isinf(value):
        return value
    return math.floor(round(value * 100, 6)) / 100


# =============================================================================
# 1. Initial input
# =============================================================================

def read_data_lines(path):
    """Return the non-blank lines of a text file, stripped of whitespace."""
    try:
        with open(path, "r", encoding="utf-8-sig") as file:
            text = file.read()
    except OSError as error:
        raise InputError(f"cannot open '{path}': {error.strerror}")
    except UnicodeDecodeError:
        raise InputError(f"'{path}' is not a UTF-8 text file")
    return [line.strip() for line in text.splitlines() if line.strip()]


def remove_count_line(lines, path):
    """Check the first line (the event count) and return the remaining lines."""
    if not lines:
        raise InputError(f"{path}: file is empty")
    try:
        count = int(lines[0])
    except ValueError:
        raise InputError(f"{path}: first line must be an integer count, got '{lines[0]}'")
    if count <= 0:
        raise InputError(f"{path}: event count must be positive, got {count}")

    event_lines = lines[1:]
    if len(event_lines) != count:
        raise InputError(f"{path}: header says {count} events but "
                         f"{len(event_lines)} event lines found")
    return event_lines


def split_fields(line, expected_count, path, line_number):
    """Split 'a:b:c:' into fields. The trailing colon is optional."""
    fields = line.split(":")
    if fields[-1].strip() == "":
        fields = fields[:-1]
    if len(fields) != expected_count:
        raise InputError(f"{path} line {line_number}: expected {expected_count} fields, "
                         f"got {len(fields)} in '{line}'")
    return [field.strip() for field in fields]


def check_name(name, path, line_number):
    if not name:
        raise InputError(f"{path} line {line_number}: empty event name")
    if "|" in name:
        # '|' separates the fields of the log file, so it cannot appear in a name
        raise InputError(f"{path} line {line_number}: event name '{name}' must not contain '|'")


def parse_number(text, description, path, line_number):
    try:
        value = float(text)
    except ValueError:
        raise InputError(f"{path} line {line_number}: {description} '{text}' is not a number")
    if math.isnan(value) or math.isinf(value):
        raise InputError(f"{path} line {line_number}: {description} '{text}' "
                         f"is not a finite number")
    return value


def parse_event_line(line, path, line_number):
    """Turn 'name:C|D:min:max:weight:' into an Event, checking every field."""
    name, kind, min_text, max_text, weight_text = split_fields(line, 5, path, line_number)
    check_name(name, path, line_number)
    where = f"{path} line {line_number}"

    kind = kind.upper()
    if kind not in ("C", "D"):
        raise InputError(f"{where}: type must be C or D, got '{kind}'")

    # A blank minimum is assumed to be 0; a blank maximum means "no limit".
    minimum = parse_number(min_text, "minimum", path, line_number) if min_text else 0.0
    maximum = parse_number(max_text, "maximum", path, line_number) if max_text else math.inf
    if minimum < 0:
        raise InputError(f"{where}: minimum for '{name}' is negative")
    if maximum < minimum:
        raise InputError(f"{where}: maximum ({maximum}) < minimum ({minimum}) for '{name}'")

    if kind == "D":
        for label, bound in (("minimum", minimum), ("maximum", maximum)):
            if not math.isinf(bound) and bound != int(bound):
                raise InputError(f"{where}: discrete event '{name}' has "
                                 f"non-integer {label} {bound}")
    elif round_up_to_cents(minimum) > round_down_to_cents(maximum):
        raise InputError(f"{where}: range [{minimum}, {maximum}] for '{name}' "
                         f"contains no value with two decimal places")

    try:
        weight = int(weight_text)
    except ValueError:
        raise InputError(f"{where}: weight '{weight_text}' is not an integer")
    if weight <= 0:
        raise InputError(f"{where}: weight must be a positive integer, got {weight}")

    return Event(name, kind, minimum, maximum, weight)


def load_events(path):
    """Read Events.txt. Returns (events by key, list of keys in file order)."""
    events = {}
    event_order = []
    for line_number, line in enumerate(remove_count_line(read_data_lines(path), path), start=2):
        event = parse_event_line(line, path, line_number)
        key = normalise_name(event.name)
        if key in events:
            raise InputError(f"{path} line {line_number}: duplicate event '{event.name}'")
        events[key] = event
        event_order.append(key)
    return events, event_order


def load_stats(path):
    """Read a stats file. Returns {event key: Stat}."""
    stats = {}
    for line_number, line in enumerate(remove_count_line(read_data_lines(path), path), start=2):
        name, mean_text, std_text = split_fields(line, 3, path, line_number)
        check_name(name, path, line_number)
        mean = parse_number(mean_text, "mean", path, line_number)
        std = parse_number(std_text, "standard deviation", path, line_number)
        if std < 0:
            raise InputError(f"{path} line {line_number}: standard deviation for "
                             f"'{name}' is negative")

        key = normalise_name(name)
        if key in stats:
            raise InputError(f"{path} line {line_number}: duplicate event '{name}'")
        stats[key] = Stat(name, mean, std)
    return stats


def distribution_warnings(event, stat, stats_path):
    """Warnings about a distribution that is usable but questionable."""
    warnings = []
    if stat.name != event.name:
        warnings.append(f"'{stat.name}' in {stats_path} matched to '{event.name}' "
                        f"(case/whitespace differs)")
    if stat.std == 0:
        warnings.append(f"'{event.name}': standard deviation is 0 - every day will be identical")
    if event.is_discrete and 0 < stat.std < 0.5:
        warnings.append(f"'{event.name}': std dev {stat.std} is small relative to integer "
                        f"rounding; generated spread will not match closely")

    low = stat.mean - 2 * stat.std
    high = stat.mean + 2 * stat.std
    if low < event.minimum or high > event.maximum:
        warnings.append(f"'{event.name}': mean +/- 2 std dev ({low:.2f} .. {high:.2f}) extends "
                        f"past the allowed range; values will be truncated so the generated "
                        f"mean/std dev may drift from the targets")
    return warnings


def check_consistency(events, event_order, stats, stats_path):
    """
    Cross-check Events.txt against a stats file.
    Fatal problems raise InputError; usable-but-questionable ones are returned as warnings.
    """
    errors = []
    missing = [events[key].name for key in event_order if key not in stats]
    unknown = [stat.name for key, stat in stats.items() if key not in events]
    if missing:
        errors.append(f"events with no statistics in {stats_path}: {', '.join(missing)}")
    if unknown:
        errors.append(f"statistics for unknown events in {stats_path}: {', '.join(unknown)}")

    warnings = []
    for key in event_order:
        if key not in stats:
            continue
        event, stat = events[key], stats[key]
        if not event.minimum <= stat.mean <= event.maximum:
            errors.append(f"'{event.name}': mean {stat.mean} is outside the allowed range "
                          f"[{event.format_value(event.minimum)}, {event.format_maximum()}]")
            continue
        warnings.extend(distribution_warnings(event, stat, stats_path))

    if errors:
        raise InputError("inconsistent input:\n    " + "\n    ".join(errors))
    return warnings


def print_setup_table(events, event_order, stats, title):
    print(f"\n{title}")
    header = (f"  {'Event':<18}{'Type':<13}{'Min':>8}{'Max':>10}{'Weight':>8}"
              f"{'Mean':>10}{'Std dev':>10}")
    print(header)
    print("  " + "-" * (len(header) - 2))
    for key in event_order:
        event, stat = events[key], stats[key]
        kind = "Discrete" if event.is_discrete else "Continuous"
        print(f"  {event.name:<18}{kind:<13}{event.format_value(event.minimum):>8}"
              f"{event.format_maximum():>10}{event.weight:>8}{stat.mean:>10.2f}{stat.std:>10.2f}")


# =============================================================================
# 2. Activity engine
# =============================================================================

def draw_daily_total(event, stat, rng):
    """
    Draw one day's total from N(mean, std), rounded to an integer (discrete) or two
    decimals (continuous). Draws outside [min, max] are discarded and redrawn, giving
    a truncated normal distribution. If that keeps failing, clamp to the nearest
    allowed value so the loop always ends and the value is always in range.
    """
    value = stat.mean
    for _ in range(MAX_REDRAWS):
        value = rng.gauss(stat.mean, stat.std)
        value = round(value) if event.is_discrete else round(value, 2)
        if event.minimum <= value <= event.maximum:
            return value

    if event.is_discrete:   # discrete bounds are integers, so rounding stays in range
        return round(min(max(value, event.minimum), event.maximum))
    lowest = round_up_to_cents(event.minimum)
    highest = round_down_to_cents(event.maximum)
    return min(max(round(value, 2), lowest), highest)


def split_into_sessions(total, rng):
    """
    Split a continuous daily total into 1-5 occurrences (e.g. online sessions).
    Works in whole hundredths so the pieces add back to the total exactly at
    two-decimal precision.
    """
    hundredths = int(round(total * 100))
    if hundredths == 0:
        return []
    session_count = min(rng.randint(1, MAX_SESSIONS_PER_DAY), hundredths)
    cut_points = sorted(rng.sample(range(1, hundredths), session_count - 1))
    boundaries = [0] + cut_points + [hundredths]
    return [(boundaries[i + 1] - boundaries[i]) / 100 for i in range(session_count)]


def generate_day(events, event_order, stats, rng):
    """Return one day's records as (seconds since midnight, event key, value), by time."""
    records = []
    for key in event_order:
        event = events[key]
        total = draw_daily_total(event, stats[key], rng)
        if event.is_discrete:
            occurrences = [1] * int(total)     # discrete events happen one at a time
        else:
            occurrences = split_into_sessions(total, rng)
        for value in occurrences:
            records.append((rng.randrange(SECONDS_PER_DAY), key, value))
    records.sort(key=lambda record: record[0])
    return records


def format_time(seconds):
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def run_activity_engine(events, event_order, stats, days, log_path, label, rng):
    print(f"\n[Activity engine] Generating {days} day(s) of {label} events -> {log_path}")
    progress_interval = math.ceil(days / MAX_PROGRESS_LINES)
    record_count = 0

    with open(log_path, "w", encoding="utf-8") as log:
        log.write(f"# Activity log ({label})\n")
        log.write(f"# Days: {days}\n")
        log.write("# Format: Day | Time | Event | Value\n")
        for day in range(1, days + 1):
            for seconds, key, value in generate_day(events, event_order, stats, rng):
                event = events[key]
                log.write(f"{day} | {format_time(seconds)} | {event.name} | "
                          f"{event.format_value(value)}\n")
                record_count += 1
            if day % progress_interval == 0 or day == days:
                print(f"  ... day {day}/{days} done")
        log.write(f"# End of log: {record_count} events\n")

    print(f"[Activity engine] Event generation complete: {record_count} events logged.")


# =============================================================================
# 3. Analysis engine
# =============================================================================

def parse_log_record(line):
    """
    Parse 'day | time | event | value'. Returns (day, event name, value), or None
    if the line is malformed or the value is not a finite number >= 0.
    """
    fields = [field.strip() for field in line.split("|")]
    if len(fields) != 4:
        return None
    day_text, _time, name, value_text = fields
    try:
        day, value = int(day_text), float(value_text)
    except ValueError:
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return day, name, value


def read_log(log_path, events, event_order):
    """Read a log file back into a list of {event key: daily total}, one entry per day."""
    days = None
    declared_count = None        # from the '# End of log' footer
    record_count = 0
    totals_by_day = {}

    # errors="replace": a corrupted byte makes that line malformed, not a crash
    with open(log_path, "r", encoding="utf-8", errors="replace") as log:
        for line_number, line in enumerate(log, start=1):
            line = line.strip()
            if not line:
                continue

            if line.startswith("#"):
                days_match = re.match(r"#\s*Days:\s*(\d+)", line)
                end_match = re.match(r"#\s*End of log:\s*(\d+)", line)
                if days_match:
                    days = int(days_match.group(1))
                if end_match:
                    declared_count = int(end_match.group(1))
                continue

            record = parse_log_record(line)
            if record is None:
                print(f"  warning: {log_path} line {line_number} malformed, skipped")
                continue
            day, name, value = record
            key = normalise_name(name)
            if key not in events:
                print(f"  warning: {log_path} line {line_number} unknown event '{name}', skipped")
                continue
            if days is not None and not 1 <= day <= days:
                print(f"  warning: {log_path} line {line_number} day {day} "
                      f"outside 1..{days}, skipped")
                continue

            record_count += 1
            day_totals = totals_by_day.setdefault(day, {})
            day_totals[key] = day_totals.get(key, 0.0) + value

    if declared_count is None:
        print(f"  warning: {log_path} has no end-of-log marker - the log may be "
              f"truncated; missing days will be counted as zero")
    elif declared_count != record_count:
        print(f"  warning: {log_path} declares {declared_count} events "
              f"but {record_count} were read")

    if days is None:
        days = max(totals_by_day, default=0)

    # A day or event with no records still counts, with a total of 0.
    return [{key: round(totals_by_day.get(day, {}).get(key, 0.0), 2) for key in event_order}
            for day in range(1, days + 1)]


def compute_statistics(daily_totals, event_order):
    """
    Mean and sample standard deviation (n - 1) of the daily totals for each event.
    The baseline is a sample of the user's behaviour, not every day there will ever
    be, so the sample formula is the unbiased choice. One day has no spread: std 0.
    """
    result = {}
    for key in event_order:
        values = [day[key] for day in daily_totals]
        mean = statistics.fmean(values) if values else 0.0
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        result[key] = (mean, std)
    return result


def write_totals_file(totals_path, label, events, event_order, daily_totals, measured):
    with open(totals_path, "w", encoding="utf-8") as file:
        file.write(f"# Daily totals ({label})\n")
        file.write("# Format: Day:" + ":".join(events[key].name for key in event_order) + ":\n")
        for day_number, day in enumerate(daily_totals, start=1):
            values = [events[key].format_value(day[key]) for key in event_order]
            file.write(f"{day_number}:" + ":".join(values) + ":\n")

        file.write("\n# Statistics (same format as Stats.txt)\n")
        file.write("# Format: Event name:mean:standard deviation:\n")
        file.write(f"{len(event_order)}\n")
        for key in event_order:
            mean, std = measured[key]
            file.write(f"{events[key].name}:{mean:.2f}:{std:.2f}:\n")


def print_measured_statistics(label, events, event_order, measured, targets):
    print(f"\n  {label.capitalize()} statistics measured from the log:")
    print(f"  {'Event':<18}{'Mean':>10}{'Std dev':>10}{'Target mean':>14}{'Target std':>12}")
    for key in event_order:
        mean, std = measured[key]
        target = targets[key]
        print(f"  {events[key].name:<18}{mean:>10.2f}{std:>10.2f}"
              f"{target.mean:>14.2f}{target.std:>12.2f}")


def run_analysis_engine(events, event_order, log_path, totals_path, label, targets):
    print(f"\n[Analysis engine] Starting analysis of {label} data from {log_path}")
    daily_totals = read_log(log_path, events, event_order)
    print(f"  ... read {len(daily_totals)} day(s) of activity")

    measured = compute_statistics(daily_totals, event_order)
    write_totals_file(totals_path, label, events, event_order, daily_totals, measured)
    print(f"  ... daily totals and statistics written to {totals_path}")

    print_measured_statistics(label, events, event_order, measured, targets)
    print("[Analysis engine] Analysis complete.")
    return daily_totals, measured


# =============================================================================
# 4. Alert engine
# =============================================================================

def effective_std(event, baseline_std):
    """
    Standard deviation used to score deviations: the baseline std itself, unless
    it is exactly 0 (one-day or constant baseline), which would mean dividing by
    zero. In that case half the event's resolution is used, so the smallest
    possible change (1 for discrete, 0.01 for continuous) counts as 2 standard
    deviations, i.e. clearly unusual.
    """
    if baseline_std > 0:
        return baseline_std
    return event.resolution / 2


def anomaly_counter(day_totals, baseline, events, event_order):
    """Sum over events of weight * |value - baseline mean| / baseline std dev."""
    counter = 0.0
    for key in event_order:
        event = events[key]
        mean, std = baseline[key]
        deviations = abs(day_totals[key] - mean) / effective_std(event, std)
        counter += deviations * event.weight
    return counter


def ask(prompt_text):
    """Read one line from the user; None at end of input (Ctrl-D / Ctrl-Z)."""
    try:
        return input(prompt_text).strip()
    except EOFError:
        return None


def parse_positive_int(text):
    """The integer in text if it is a whole number > 0, otherwise None."""
    try:
        number = int(text)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def wants_to_quit(answer):
    return answer is None or answer.lower() in QUIT_WORDS


def ask_for_live_stats(events, event_order):
    """Prompt until a valid stats file is given. Returns (path, stats) or None to quit."""
    while True:
        path = ask("\nEnter a statistics file for live data (or 'q' to quit): ")
        if wants_to_quit(path):
            return None
        if not path:
            continue
        try:
            stats = load_stats(path)
            for warning in check_consistency(events, event_order, stats, path):
                print(f"  warning: {warning}")
        except InputError as error:
            print(f"  error: {error}")
            continue
        return path, stats


def ask_for_days():
    """Prompt until a positive integer is given. Returns the number or None to quit."""
    while True:
        answer = ask("Enter number of days to generate (or 'q' to quit): ")
        if wants_to_quit(answer):
            return None
        days = parse_positive_int(answer)
        if days is not None:
            return days
        print("  please enter a positive integer")


def report_days(daily_totals, baseline, events, event_order, threshold):
    print(f"\n[Alert engine] Checking {len(daily_totals)} day(s) against the baseline "
          f"(threshold {threshold})")
    print(f"  {'Day':>5}{'Threshold':>12}{'Anomaly counter':>18}  Status")
    flagged_count = 0
    for day_number, day in enumerate(daily_totals, start=1):
        counter = anomaly_counter(day, baseline, events, event_order)
        flagged = counter >= threshold
        flagged_count += flagged
        status = "FLAGGED (alert)" if flagged else "okay"
        print(f"  {day_number:>5}{threshold:>12.2f}{counter:>18.2f}  {status}")
    print(f"[Alert engine] {flagged_count} of {len(daily_totals)} day(s) flagged.")


def warn_about_zero_baseline_std(events, event_order, baseline):
    constant = [events[key].name for key in event_order if baseline[key][1] == 0]
    if constant:
        print(f"  warning: baseline std dev is 0 for {', '.join(constant)}; using half "
              f"the smallest recordable change (0.5 discrete, 0.005 continuous) instead")


def run_alert_engine(events, event_order, baseline, rng):
    threshold = 2 * sum(events[key].weight for key in event_order)
    print("\n" + "=" * 70)
    print("ALERT ENGINE")
    print(f"Anomaly threshold = 2 x (sum of weights) = {threshold}")
    warn_about_zero_baseline_std(events, event_order, baseline)
    print("=" * 70)

    run_number = 0
    while True:
        choice = ask_for_live_stats(events, event_order)
        if choice is None:
            break
        stats_path, live_stats = choice
        days = ask_for_days()
        if days is None:
            break

        run_number += 1
        label = f"live run {run_number}"
        log_path = os.path.join(OUTPUT_DIR, f"live{run_number}_log.txt")
        totals_path = os.path.join(OUTPUT_DIR, f"live{run_number}_totals.txt")

        print_setup_table(events, event_order, live_stats,
                          f"Live statistics loaded from {stats_path}:")
        try:
            run_activity_engine(events, event_order, live_stats, days, log_path, label, rng)
            daily_totals, _ = run_analysis_engine(events, event_order, log_path, totals_path,
                                                  label, live_stats)
        except OSError as error:
            print(f"  error: could not write or read the {label} files: {error}")
            continue
        report_days(daily_totals, baseline, events, event_order, threshold)

    print("Exiting IDS.")


# =============================================================================
# Main
# =============================================================================

def parse_arguments(argv):
    """Returns (events path, stats path, days, seed or None). Raises InputError."""
    if len(argv) not in (4, 5):
        raise InputError(USAGE)
    events_path, stats_path, days_text = argv[1:4]

    days = parse_positive_int(days_text)
    if days is None:
        raise InputError(f"Days must be a positive integer, got '{days_text}'")

    seed = None
    if len(argv) == 5:
        try:
            seed = int(argv[4])
        except ValueError:
            raise InputError(f"seed must be an integer, got '{argv[4]}'")
    return events_path, stats_path, days, seed


def print_banner(title):
    print("=" * 70)
    print(title)
    print("=" * 70)


def main(argv):
    try:
        events_path, stats_path, days, seed = parse_arguments(argv)
    except InputError as error:
        message = str(error)
        print(message if message == USAGE else f"error: {message}")
        return 1

    print_banner("INITIAL INPUT")
    try:
        events, event_order = load_events(events_path)
        print(f"Read {len(event_order)} event(s) from {events_path}")
        stats = load_stats(stats_path)
        print(f"Read {len(stats)} statistic(s) from {stats_path}")
        warnings = check_consistency(events, event_order, stats, stats_path)
    except InputError as error:
        print(f"error: {error}")
        return 1

    for warning in warnings:
        print(f"  warning: {warning}")
    if not warnings:
        print("Events and statistics are consistent.")
    print_setup_table(events, event_order, stats, "Events and baseline statistics:")

    rng = random.Random(seed)    # with a seed, the whole session is reproducible
    if seed is not None:
        print(f"\nRandom seed: {seed}")

    print()
    print_banner("BASELINE: ACTIVITY ENGINE + ANALYSIS ENGINE")
    log_path = os.path.join(OUTPUT_DIR, "baseline_log.txt")
    totals_path = os.path.join(OUTPUT_DIR, "baseline_totals.txt")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        run_activity_engine(events, event_order, stats, days, log_path, "baseline", rng)
        _, baseline = run_analysis_engine(events, event_order, log_path, totals_path,
                                          "baseline", stats)
    except OSError as error:
        print(f"error: could not write or read the baseline files: {error}")
        return 1

    run_alert_engine(events, event_order, baseline, rng)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
