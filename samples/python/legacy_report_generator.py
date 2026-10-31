"""Legacy reporting module used as a code-smell test fixture (every smell is labelled)."""
import os  # EXPECT: UNUSED_IMPORT
import sys  # EXPECT: UNUSED_IMPORT
import json  # EXPECT: UNUSED_IMPORT
from math import *  # EXPECT: WILDCARD_IMPORT

COUNTER = 0


def build_report(rows, fmt, title, author, footer, locale, cache=[]):  # EXPECT: LONG_PARAMETER_LIST, MUTABLE_DEFAULT
    """Build a report from rows."""
    global COUNTER  # EXPECT: GLOBAL_STATE
    COUNTER += 1
    out = []
    if rows == None:  # EXPECT: COMPARE_NONE
        return out
    for row in rows:
        out.append(str(row))
    return out


def classify(order):  # EXPECT: HIGH_COMPLEXITY, DEEP_NESTING
    """Classify an order into a processing lane."""
    if order.total > 5000:  # EXPECT: MAGIC_NUMBER
        if order.customer.vip:
            if order.items:
                for item in order.items:
                    if item.weight > 20 and item.fragile:  # EXPECT: MAGIC_NUMBER
                        return "special"
                    elif item.weight > 20 or item.hazardous:  # EXPECT: MAGIC_NUMBER
                        return "freight"
                    elif item.qty > 5 and item.region == "EU":  # EXPECT: MAGIC_NUMBER
                        return "bulk-eu"
                    elif item.qty > 5 and item.region == "US":  # EXPECT: MAGIC_NUMBER
                        return "bulk-us"
                    elif item.digital:
                        return "digital"
    elif order.total > 1000 and order.customer.vip:
        return "priority"
    elif order.total > 1000 and order.express:
        return "express"
    elif order.coupon or order.gift or order.preorder:
        return "promo"
    return "standard"


def parse_file(path):  # EXPECT: LONG_FUNCTION, HIGH_COMPLEXITY
    """Parse a data file into a list of records."""
    records = []
    with open(path) as fh:
        lines = fh.readlines()
    header = lines[0].strip().split(",")
    for line in lines[1:]:
        parts = line.strip().split(",")
        record = {}
        for index, name in enumerate(header):
            record[name] = parts[index]
        records.append(record)
    cleaned = []
    for record in records:
        for key in record:
            record[key] = record[key].strip()
        cleaned.append(record)
    totals = {}
    for record in cleaned:
        key = record.get("category", "none")
        totals[key] = totals.get(key, 0) + 1
    result = []
    for key in totals:
        result.append((key, totals[key]))
    result.sort()
    labels = {}
    for key, value in result:
        labels[key] = key.upper()
    for key in labels:
        if labels[key] == "":
            labels[key] = "UNKNOWN"
    ordered = sorted(labels.items())
    seen_names = set()
    for key, label in ordered:
        seen_names.add(key)
    report_lines = []
    for name in sorted(seen_names):
        report_lines.append(name)
    print(len(report_lines))
    for key, label in ordered:
        cleaned.append({"label": label, "name": key})
    summary = []
    for key, value in result:
        summary.append(key + "=" + str(value))
    text = ";".join(summary)
    print(text)
    return cleaned


def save_all(items):
    """Save items, ignoring errors."""
    for item in items:
        try:
            item.save()
        except:  # EXPECT: BARE_EXCEPT, EMPTY_EXCEPT
            pass


def load_all(items):
    """Load items and hide every failure."""
    for item in items:
        try:
            item.load()
        except Exception:  # EXPECT: BROAD_EXCEPT
            print("failed")


def export_csv(rows, path):
    """Write rows to a CSV file."""
    header = ",".join(rows[0].keys())
    body = []
    for row in rows:
        values = [str(v) for v in row.values()]
        body.append(",".join(values))
    with open(path, "w") as fh:
        fh.write(header + "\n")
        fh.write("\n".join(body))


def export_tsv(rows, path):
    """Write rows to a TSV file."""
    header = ",".join(rows[0].keys())
    body = []
    for row in rows:
        values = [str(v) for v in row.values()]
        body.append(",".join(values))  # EXPECT: DUPLICATE_CODE
    with open(path, "w") as fh:
        fh.write(header + "\n")
        fh.write("\n".join(body))


def area(radius):
    """Return a circle area."""
    return 3.14159 * radius * radius  # EXPECT: MAGIC_NUMBER


def early_exit(value):
    """Return early."""
    if value:
        return 1
    return value



class ReportManager:  # EXPECT: GOD_CLASS
    """Does far too much."""

    def step_1(self):
        """Run step 1."""
        return len(self.__dict__)

    def step_2(self):
        """Run step 2."""
        return len(self.__dict__)

    def step_3(self):
        """Run step 3."""
        return len(self.__dict__)

    def step_4(self):
        """Run step 4."""
        return len(self.__dict__)

    def step_5(self):
        """Run step 5."""
        return len(self.__dict__)

    def step_6(self):
        """Run step 6."""
        return len(self.__dict__)

    def step_7(self):
        """Run step 7."""
        return len(self.__dict__)

    def step_8(self):
        """Run step 8."""
        return len(self.__dict__)

    def step_9(self):
        """Run step 9."""
        return len(self.__dict__)

    def step_10(self):
        """Run step 10."""
        return len(self.__dict__)

    def step_11(self):
        """Run step 11."""
        return len(self.__dict__)

    def step_12(self):
        """Run step 12."""
        return len(self.__dict__)

    def step_13(self):
        """Run step 13."""
        return len(self.__dict__)

    def step_14(self):
        """Run step 14."""
        return len(self.__dict__)

    def step_15(self):
        """Run step 15."""
        return len(self.__dict__)

    def step_16(self):
        """Run step 16."""
        return len(self.__dict__)

    def step_17(self):
        """Run step 17."""
        return len(self.__dict__)

    def step_18(self):
        """Run step 18."""
        return len(self.__dict__)

    def step_19(self):
        """Run step 19."""
        return len(self.__dict__)

    def step_20(self):
        """Run step 20."""
        return len(self.__dict__)

    def step_21(self):
        """Run step 21."""
        return len(self.__dict__)

    def step_22(self):
        """Run step 22."""
        return len(self.__dict__)
