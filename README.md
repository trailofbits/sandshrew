# sandshrew

sandshrew is a concolic execution tool for cryptographic verification. It harnesses the [Manticore](https://github.com/trailofbits/manticore) API in order to perform concolic execution on C cryptographic primitives.

Classical symbolic execution is generally not feasible when analyzing crypto, due to the presence of complex symbolic expressions. sandshrew fixes this problem by concretizing (or, "emulating") the execution of specified cryptographic primitives, avoiding complex SMT queries and creating a speedup in the analysis.

## Features

* Automatic testcase generation for analysis
* Easy interface for writing crypto unit tests
* Integration into development workflows (imagine formal verification for unit testing)
* Works in under 300 LOCs

## Installation

```
$ git clone https://github.com/trailofbits/sandshrew && cd sandshrew/
$ python setup.py install
```

To hack and develop on sandshrew, it is recommended to utilize a Python `virtualenv`.

## Example Test cases

1. `test_simple`

## License
