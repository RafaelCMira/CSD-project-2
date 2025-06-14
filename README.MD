| Student nº | Name        | email                     |
| ---------- | ----------- | ------------------------- |
| 59243      | Rafael Mira | rs.mira@campus.fct.unl.pt |

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
But if yout cpu has more threads than cpus, use the number of threads instead of auto, e.g. -n 12

```bash
pytest .\unitTest -n auto
```

# How to run the code

To run the code, you can use the following command.
Note, you can override the default configuration by using those parameters:

```bash
python .\taps.py --nodes ..\inputs\tor_consensus.json --config ..\inputs\input1.json
```

This will output the guard, middle, and exit nodes with their respective fingerprint, country and ASN number.
The output will be something like this:

```
  Guard: CAF71D173C0E703B6E1E0960D0249627EA2AC2C5 | AL | 215540
  Middle: F922C23FF68AAADBD2C9A384471B63694A879BA5 | PL | 210558
  Exit: 5AFEF0FF40762591B555248D25487E797E732B4D | UA | 207656
```
