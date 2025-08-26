[![codecov](https://codecov.io/gh/sharkiqlibs/sharkiq/graph/badge.svg?token=DO96BWVXA7)](https://codecov.io/gh/sharkiqlibs/sharkiq)
[![PyPI](https://img.shields.io/pypi/v/sharkiq)](https://pypi.org/project/sharkiq/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/sharkiq)](https://pypi.org/project/sharkiq/)
[![GitHub](https://img.shields.io/github/license/sharkiqlibs/sharkiq)](https://github.com/sharkiqlibs/sharkiq)
[![Documentation](https://img.shields.io/badge/Documentation-2c3e50)](https://sharkiqlibs.github.io/sharkiq/)
# sharkiq
Unofficial SDK for Shark IQ robot vacuums, designed primarily to support an integration for [Home Assistant](https://www.home-assistant.io/).

This library is heavily based off of [sharkiq](https://github.com/ajmarks/sharkiq) by [@ajmarks](https://github.com/ajmarks), with a few minor changes to allow it to work on newer versions of the Shark API.

## Installation

```bash
pip install sharkiq
```

## Usage
Examples can be found in the [examples directory](examples/).

## Documentation
You can view the latest documentation [here](https://sharkiqlibs.github.io/sharkiq/).

## TODOs:
 * Add support for mapping
 * Once we have mapping, it may be possible to use the RSSI property combined with an increased update frequency
 to generate a wifi strength heatmap.  Kind of orthogonal to the main purpose, but I really want to do this.
 
## License
[MIT](https://choosealicense.com/licenses/mit/)