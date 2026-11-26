# VulPulse example source plugin

This package demonstrates the `vulpulse.sources` entry-point contract. It
emits one synthetic record and does not contact any external service.

Install VulPulse first, then install this example without resolving its
`vulpulse` dependency from PyPI:

```bash
pip install -e examples/plugins/vulpulse-example-source --no-deps
vulpulse plugins
vulpulse crawl --source example
```

Remove the package when you are done:

```bash
pip uninstall vulpulse-example-source
```

For a real plugin, replace `ExampleSource.fetch` with a public feed client,
declare a sensible `default_interval_minutes`, and keep the
`vulpulse.sources` entry point in `pyproject.toml`. Plugin code runs in the
VulPulse process; install only plugins you trust.
