# Development Guide

Development instructions for contributing to Heimdall.

## Project Structure

```
heimdall/
├── setup.py                # Package installation configuration
├── requirements.txt        # Python dependencies
├── README.md              # Main project documentation
├── INSTALL.md             # Installation guide
├── RULES.md               # Rule format documentation
├── DEVELOPMENT.md         # This file
├── LICENSE                # MIT License
├── .gitignore             # Git exclusions
├── main.py                # Legacy entry point (deprecated, use python -m heimdall)
├── debugging.py           # Debug scripts
├── heimdall/              # Main package
│   ├── __init__.py        # Package initialization
│   ├── __main__.py        # Entry point for python -m heimdall
│   ├── cli.py             # Command-line interface
│   ├── sniffer.py         # Packet sniffing and output
│   ├── detector.py        # Rule matching and alerts
│   ├── logger.py          # Alert logging
│   ├── packet_logger.py   # Packet organization and logging
│   ├── rules.py           # Rule loading and validation
│   ├── _imports.py        # Lazy imports for optional dependencies
│   ├── utils.py           # Utility functions
│   └── __pycache__/
└── rules/                 # Sample rules
    └── rules.json         # Default detection rules
```

## Development Setup

### 1. Clone and Install (Editable Mode)

```bash
git clone https://github.com/yourusername/heimdall.git
cd heimdall
pip install -e .
```

The `-e` flag installs in editable mode, so code changes are reflected immediately.

### 2. Run Commands

After installation, use either:

```bash
# Method 1: Direct module execution
python -m heimdall sniffer -li

# Method 2: Installed console script
heimdall sniffer -li

# Method 3: Legacy main.py (deprecated)
python main.py sniffer -li
```

### 3. Install Development Dependencies

```bash
pip install pytest pytest-cov black flake8
```

## Common Development Tasks

### Testing with Live Traffic

```bash
# Sniff on local interface
python -m heimdall sniffer -i eth0 -n 10
```

### Testing Rules

```bash
python -m heimdall detector --rules rules/rules.json -i eth0 --alert-format json
```

### Code Formatting

```bash
black heimdall/
```

### Linting

```bash
flake8 heimdall/ --max-line-length=120
```

## Adding New Features

### 1. Add a New Detection Mode

1. Create the mode function in `heimdall/cli.py`
2. Add argument parser in `get_args()`
3. Add case in `main()` function

Example:

```python
# In cli.py
def run_newmode(args):
    """Run new detection mode."""
    print("New mode running")

# In get_args()
newmode = sub.add_parser("newmode", help="Run new detection mode")
newmode.add_argument("--option", help="Option description")

# In main()
elif args.mode == "newmode":
    run_newmode(args)
```

### 2. Add New Rule Fields

1. Update `Rule` dataclass in `heimdall/rules.py`
2. Update validation in `_normalize_rule()`
3. Update matching logic in `Detector.match_event()`
4. Document in `RULES.md`

### 3. Add Output Format

1. Add function to `heimdall/sniffer.py`
2. Add to `_handle_packet_output()` display choices
3. Update CLI argument choices

## Testing

### Run Unit Tests

```bash
pytest tests/ -v
```

### Test Coverage

```bash
pytest --cov=heimdall tests/
```

### Manual Testing Checklist

- [ ] Sniffer mode on live interface
- [ ] Sniffer mode offline (PCAP)
- [ ] All display formats (brief, verbose, hexdump, json, pcap)
- [ ] Detector with live interface
- [ ] Detector with PCAP file
- [ ] Logger with live interface
- [ ] Logger with PCAP file
- [ ] All organization strategies (date, protocol, src_ip, dst_ip, none)
- [ ] JSON and YAML rules loading
- [ ] Alert output formats (fast, json)
- [ ] Custom rules matching

## Release Checklist

Before releasing a new version:

1. **Update version**
   - Edit `setup.py` version number
   - Update CHANGELOG.md if exists

2. **Test thoroughly**

   ```bash
   pytest tests/
   black --check heimdall/
   flake8 heimdall/
   ```

3. **Update documentation**
   - README.md
   - RULES.md
   - INSTALL.md

4. **Commit and tag**

   ```bash
   git commit -m "Release v0.2.0"
   git tag -a v0.2.0 -m "Version 0.2.0"
   git push origin main --tags
   ```

5. **Build and publish** (if using PyPI)
   ```bash
   python -m build
   python -m twine upload dist/*
   ```

## Debugging

### Enable Verbose Logging

Set logging level in mode functions:

```python
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
```

### Inspect Packets

Use `debugging.py` for packet inspection:

```bash
python debugging.py
```

### Rule Matching Debug

Add debug prints in `Detector.match_event()`:

```python
logging.debug(f"Matching packet: {event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port}")
```

## Code Style

- **Python Version:** 3.10+
- **Style:** PEP 8 (Black formatter)
- **Type Hints:** Recommended but not required
- **Docstrings:** Required for public functions

## Reporting Issues

When reporting bugs, include:

- OS and Python version
- Full error traceback
- Command you ran
- Sample PCAP if applicable
- Rules file if applicable

## Contributing

See main README.md for contribution guidelines.
