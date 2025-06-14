# Python Libs

Im using Anaconda with Python 3.12.4 version.
Im also using the [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) database for IP geolocation.

This requires the installation of the `geoip2` package, which can be done using pip:

```bash
pip install geoip2
```

For testing i used the `pytest` package, which be installed via pip:

```bash
pip install pytest
```

And to run the tests faster (using parallelism) i also used the `pytest-xdist` package, which can be installed via pip:

```bash
pip install pytest-xdist
```

To run the tests, you can use the following command to execute them in parallel: (-n auto will automatically detect the number of available CPUs and run tests in parallel)

```bash
pytest .\unitTest -n auto
```

# How to run the code

To run the code, you can use the following command:

```bash
python .\taps.py
```
