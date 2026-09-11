import sys
import random
import string

sys.path.insert(0, "KubeSec-master")

import parser
import scanner


FUZZ_RUNS = 100
random.seed(5710)


# Generate simple random values for the functions that process YAML data.
def random_value(depth=0):
    values = [
        None,
        True,
        False,
        0,
        1,
        -1,
        "",
        "admin",
        "password",
        "secret123",
        "normal-value",
    ]

    if depth >= 3:
        return random.choice(values)

    choice = random.randint(0, 4)
    if choice == 0:
        return random.choice(values)
    if choice == 1:
        return [random_value(depth + 1) for _ in range(random.randint(0, 3))]
    if choice == 2:
        return {
            random_string(): random_value(depth + 1)
            for _ in range(random.randint(0, 3))
        }
    if choice == 3:
        return random_string()
    return random.randint(-100, 100)


def random_string():
    characters = string.ascii_letters + string.digits + "_-. /:@"
    return "".join(random.choice(characters) for _ in range(random.randint(0, 50)))


def random_path_value():
    values = [
        None,
        True,
        False,
        0,
        1,
        [],
        {},
        random_string(),
    ]
    return random.choice(values)


def run_fuzz_test(name, function, make_input):
    errors = []

    for _ in range(FUZZ_RUNS):
        args = make_input()

        try:
            function(*args)
        except Exception as error:
            errors.append((args, type(error).__name__, str(error)))

    print("\n" + name)
    print("-" * len(name))
    print("Runs:", FUZZ_RUNS)

    if len(errors) == 0:
        print("No exceptions discovered.")
    else:
        print("Exceptions discovered:", len(errors))
        for args, error_type, error_message in errors[:5]:
            print("Input:", args)
            print("Error:", error_type, error_message)

    return errors


def main():
    results = {}

    results["parser.keyMiner"] = run_fuzz_test(
        "parser.keyMiner",
        parser.keyMiner,
        lambda: (random_value(), random_value()),
    )

    results["parser.getKeyRecursively"] = run_fuzz_test(
        "parser.getKeyRecursively",
        parser.getKeyRecursively,
        lambda: (random_value(), []),
    )

    results["parser.getValuesRecursively"] = run_fuzz_test(
        "parser.getValuesRecursively",
        lambda value: list(parser.getValuesRecursively(value)),
        lambda: (random_value(),),
    )

    results["parser.getValsFromKey"] = run_fuzz_test(
        "parser.getValsFromKey",
        parser.getValsFromKey,
        lambda: (random_value(), random_string(), []),
    )

    results["parser.checkIfWeirdYAML"] = run_fuzz_test(
        "parser.checkIfWeirdYAML",
        parser.checkIfWeirdYAML,
        lambda: (random_path_value(),),
    )

    results["parser.checkIfValidHelm"] = run_fuzz_test(
        "parser.checkIfValidHelm",
        parser.checkIfValidHelm,
        lambda: (random_path_value(),),
    )

    results["scanner.isValidUserName"] = run_fuzz_test(
        "scanner.isValidUserName",
        scanner.isValidUserName,
        lambda: (random_value(),),
    )

    results["scanner.isValidPasswordName"] = run_fuzz_test(
        "scanner.isValidPasswordName",
        scanner.isValidPasswordName,
        lambda: (random_value(),),
    )

    results["scanner.checkIfValidSecret"] = run_fuzz_test(
        "scanner.checkIfValidSecret",
        scanner.checkIfValidSecret,
        lambda: (random_value(),),
    )

    results["scanner.checkIfValidKeyValue"] = run_fuzz_test(
        "scanner.checkIfValidKeyValue",
        scanner.checkIfValidKeyValue,
        lambda: (random_value(),),
    )

    total_errors = sum(len(errors) for errors in results.values())
    print("\nFuzzing complete.")
    print("Functions tested:", len(results))
    print("Total exceptions discovered:", total_errors)


if __name__ == "__main__":
    main()
